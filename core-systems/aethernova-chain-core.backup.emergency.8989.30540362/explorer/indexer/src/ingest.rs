//! explorer/indexer/src/ingest.rs
//! Промышленный ingestion-цикл Kafka: ручные коммиты, бэтчинг, DLQ, ретраи, корректное завершение.
//!
//! Ключевые факты:
//! - StreamConsumer предоставляет поток/recv без явного poll.  (docs.rs rdkafka) 
//! - Коммит в Kafka = "следующий оффсет" (offset+1).         (Confluent librdkafka docs)
//! - Ctrl-C / отмена задач — tokio::signal / CancellationToken. (Tokio docs)
//! - DLQ — FutureProducer (future по доставке).                (docs.rs rdkafka)
//! - Detach сообщения для жизни вне консьюмера.               (BorrowedMessage::detach)
//
//! Источники:
//!   - StreamConsumer: https://docs.rs/rdkafka/latest/rdkafka/consumer/struct.StreamConsumer.html
//!   - FutureProducer: https://docs.rs/rdkafka/latest/rdkafka/producer/struct.FutureProducer.html
//!   - Detach: https://docs.rs/rdkafka/latest/rdkafka/message/struct.BorrowedMessage.html#method.detach
//!   - Коммит offset+1: https://docs.confluent.io/platform/current/clients/librdkafka/html/classRdKafka_1_1KafkaConsumer.html#method-commitSync-2
//!   - tokio::select!: https://docs.rs/tokio/latest/tokio/macro.select.html
//!   - tokio::signal::ctrl_c: https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html
//!   - CancellationToken: https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html

use std::{collections::HashMap, time::{Duration, Instant}};

use anyhow::{Context, Result};
use futures::FutureExt;
use rdkafka::{
    ClientConfig,
    consumer::{Consumer, StreamConsumer, CommitMode},
    error::KafkaError,
    message::{BorrowedMessage, OwnedHeaders, OwnedMessage, Message},
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
    TopicPartitionList,
};
use tokio::{time, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, instrument};

/// Конфигурация ingestion-цикла.
#[derive(Clone, Debug)]
pub struct IngestConfig {
    /// bootstrap.servers, например "kafka-1:9092,kafka-2:9092"
    pub brokers: String,
    /// group.id консьюмера
    pub group_id: String,
    /// Список топиков к подписке
    pub topics: Vec<String>,
    /// auto.offset.reset, обычно "earliest" для индексаторов
    pub auto_offset_reset: String,
    /// Максимум сообщений в батче
    pub batch_max: usize,
    /// Максимальный возраст батча до флеша
    pub batch_max_latency: Duration,
    /// Таймаут получения одного сообщения (recv)
    pub recv_timeout: Duration,
    /// Включить/настроить DLQ
    pub dlq: Option<DlqConfig>,
    /// Параметры Kafka клиента (доп. override)
    pub extra_kafka: Vec<(String, String)>,
}

/// Конфигурация Dead-Letter Queue.
#[derive(Clone, Debug)]
pub struct DlqConfig {
    pub topic: String,
    pub headers_prefix: Option<String>, // например "x-dlq-"
    pub delivery_timeout: Duration,
}

/// Интерфейс доменной обработки батча.
/// Верните Ok => будет commit оффсетов. Err => батч уйдет в DLQ (если включен) и всё равно будет commit (чтобы не зациклиться).
#[async_trait::async_trait]
pub trait BatchSink: Send + Sync + 'static {
    async fn process(&self, batch: &[OwnedMessage]) -> Result<()>;
}

/// Запуск ingestion-потока. Возвращает JoinHandle, останавливается по токену отмены.
#[instrument(skip_all, fields(group = %cfg.group_id, topics = ?cfg.topics))]
pub async fn start_ingest<S: BatchSink>(
    cfg: IngestConfig,
    sink: S,
    cancel: CancellationToken,
) -> Result<JoinHandle<()>> {
    // Консюмер Kafka
    let consumer = build_consumer(&cfg)?;
    consumer.subscribe(&cfg.topics.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .context("subscribe() failed")?;

    // DLQ продьюсер (опционально)
    let dlq_producer = match &cfg.dlq {
        Some(_) => Some(build_producer(&cfg)?),
        None => None,
    };

    let handle = tokio::spawn(run_loop(cfg, consumer, sink, dlq_producer, cancel));
    Ok(handle)
}

fn build_consumer(cfg: &IngestConfig) -> Result<StreamConsumer> {
    let mut conf = ClientConfig::new();
    conf
        .set("bootstrap.servers", &cfg.brokers)
        .set("group.id", &cfg.group_id)
        .set("enable.auto.commit", "false") // ручные коммиты для at-least-once
        .set("enable.auto.offset.store", "false")
        .set("auto.offset.reset", &cfg.auto_offset_reset);

    for (k, v) in &cfg.extra_kafka {
        conf.set(k, v);
    }

    let consumer: StreamConsumer = conf.create().context("create StreamConsumer")?;
    Ok(consumer)
}

fn build_producer(cfg: &IngestConfig) -> Result<FutureProducer> {
    let mut conf = ClientConfig::new();
    conf.set("bootstrap.servers", &cfg.brokers);

    // типичные оптимизации производительности можно добавить здесь (linger.ms, batch.size и т.п.)
    let prod: FutureProducer = conf.create().context("create FutureProducer")?;
    Ok(prod)
}

#[instrument(skip_all)]
async fn run_loop<S: BatchSink>(
    cfg: IngestConfig,
    consumer: StreamConsumer,
    sink: S,
    dlq: Option<FutureProducer>,
    cancel: CancellationToken,
) {
    info!("ingest: started");
    let mut batch: Vec<OwnedMessage> = Vec::with_capacity(cfg.batch_max);
    let mut last_flush = Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("ingest: cancellation requested");
                if !batch.is_empty() {
                    if let Err(e) = flush_batch(&cfg, &consumer, &sink, dlq.as_ref(), &mut batch).await {
                        error!(error=?e, "ingest: flush on cancel failed");
                    }
                }
                break;
            }

            // Пытаемся получить следующее сообщение с таймаутом
            res = time::timeout(cfg.recv_timeout, consumer.recv()) => {
                match res {
                    Ok(Ok(msg)) => {
                        // Переносим данные из BorrowedMessage так, чтобы пережили consumer. (detach)
                        // https://docs.rs/rdkafka/latest/rdkafka/message/struct.BorrowedMessage.html#method.detach
                        batch.push(msg.detach());
                        if batch.len() >= cfg.batch_max {
                            if let Err(e) = flush_batch(&cfg, &consumer, &sink, dlq.as_ref(), &mut batch).await {
                                error!(error=?e, "ingest: flush failed");
                            }
                            last_flush = Instant::now();
                        }
                    }
                    Ok(Err(KafkaError::PartitionEOF(_))) => {
                        // Достигнут EOF партиции — не ошибка.
                        debug!("partition EOF");
                    }
                    Ok(Err(e)) => {
                        warn!(error=?e, "ingest: recv error");
                        // можно добавить счётчик ошибок
                    }
                    Err(_elapsed) => {
                        // Таймаут чтения — проверим «возраст» батча и при необходимости сбросим.
                        if !batch.is_empty() && last_flush.elapsed() >= cfg.batch_max_latency {
                            if let Err(e) = flush_batch(&cfg, &consumer, &sink, dlq.as_ref(), &mut batch).await {
                                error!(error=?e, "ingest: flush on timeout failed");
                            }
                            last_flush = Instant::now();
                        }
                    }
                }
            }
        }
    }

    info!("ingest: stopped");
}

/// Сброс батча: доменная обработка -> (при успехе) коммит оффсетов; при ошибке — отправка в DLQ и коммит.
#[instrument(skip_all, fields(batch_len = batch.len()))]
async fn flush_batch<S: BatchSink>(
    cfg: &IngestConfig,
    consumer: &StreamConsumer,
    sink: &S,
    dlq: Option<&FutureProducer>,
    batch: &mut Vec<OwnedMessage>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    // 1) Доменная обработка
    let process_res = sink.process(batch).await;

    if let Err(err) = process_res {
        warn!(error=?err, "ingest: sink.process failed; sending to DLQ (if configured)");
        if let Some(prod) = dlq {
            dlq_forward(cfg, prod, batch).await?;
        }
        // Важно: чтобы не зациклиться на «ядовитых» сообщениях, после DLQ мы всё равно коммитим.
    }

    // 2) Коммит оффсетов (offset+1 для каждой (topic,partition))
    //    См. Confluent/librdkafka: commit(message) коммитит message.offset + 1.
    //    https://docs.confluent.io/platform/current/clients/librdkafka/html/classRdKafka_1_1KafkaConsumer.html#method-commitSync-2
    commit_batch_offsets(consumer, batch)?;

    batch.clear();
    Ok(())
}

fn commit_batch_offsets(consumer: &StreamConsumer, batch: &[OwnedMessage]) -> Result<()> {
    use rdkafka::Offset;
    let mut highmarks: HashMap<(String, i32), i64> = HashMap::new();

    for msg in batch {
        let topic = msg.topic().to_string();
        let part = msg.partition();
        let off = msg.offset();

        highmarks
            .entry((topic, part))
            .and_modify(|cur| { if off > *cur { *cur = off; } })
            .or_insert(off);
    }

    let mut tpl = TopicPartitionList::new();
    for ((topic, part), last_off) in highmarks {
        // Коммитим "следующий к чтению" оффсет
        let next = last_off + 1;
        tpl.add_partition_offset(&topic, part, Offset::Offset(next))
            .with_context(|| format!("add_partition_offset {}-{} {}", topic, part, next))?;
    }

    consumer.commit(&tpl, CommitMode::Async)
        .context("commit offsets")?;
    Ok(())
}

/// Отправка батча в DLQ с экспоненциальным бэкоффом.
#[instrument(skip_all)]
async fn dlq_forward(
    cfg: &IngestConfig,
    producer: &FutureProducer,
    batch: &[OwnedMessage],
) -> Result<()> {
    let dlq = cfg.dlq.as_ref().expect("DLQ config required for dlq_forward");
    let hdr_prefix = dlq.headers_prefix.as_deref().unwrap_or("x-dlq-");

    // Простой экспоненциальный бэкофф (можете заменить на policy по месту).
    let mut backoff = exponential_backoff::Backoff::default();
    backoff.set_max_attempts(5);

    for m in batch {
        let payload = m.payload().unwrap_or_default();
        let key = m.key();

        // Соберём «диагностические» заголовки DLQ
        let mut headers = OwnedHeaders::new();
        headers = headers
            .insert(format!("{hdr_prefix}topic"), m.topic().to_string())
            .insert(format!("{hdr_prefix}partition"), m.partition().to_string())
            .insert(format!("{hdr_prefix}offset"), m.offset().to_string());

        // Отправляем с ретраями.
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let fut = producer.send(
                FutureRecord::to(&dlq.topic)
                    .payload(payload)
                    .key_opt(key)
                    .headers(headers.clone()),
                dlq.delivery_timeout,
            );

            match fut.await {
                Ok((_part, _offset)) => break, // доставлено
                Err((e, _owned_msg)) => {
                    if let Some(wait) = backoff.next_backoff() {
                        warn!(error=?e, attempt, "dlq: delivery failed, backing off");
                        time::sleep(wait).await;
                        continue;
                    } else {
                        return Err(anyhow::anyhow!("dlq: delivery failed after retries: {e:?}"));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Утилита: из BorrowedMessage сделать OwnedMessage (если захотите использовать вне этого модуля).
pub fn to_owned(msg: &BorrowedMessage<'_>) -> OwnedMessage {
    msg.detach() // https://docs.rs/rdkafka/latest/rdkafka/message/struct.BorrowedMessage.html#method.detach
}
