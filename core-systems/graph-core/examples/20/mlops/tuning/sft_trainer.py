import torch
from torch.utils.data import DataLoader
from transformers import Trainer, TrainingArguments

class SFTTrainer:
    """
    Класс для обучения с подкреплением (Supervised Fine-Tuning) моделей на основе Transformers.
    Предназначен для дообучения языковых моделей на специализированных датасетах.
    """

    def __init__(self, model, tokenizer, train_dataset, val_dataset=None, batch_size=8, epochs=3, learning_rate=5e-5):
        self.model = model
        self.tokenizer = tokenizer
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.batch_size = batch_size
        self.epochs = epochs
        self.learning_rate = learning_rate

        self.training_args = TrainingArguments(
            output_dir="./sft_output",
            num_train_epochs=self.epochs,
            per_device_train_batch_size=self.batch_size,
            per_device_eval_batch_size=self.batch_size,
            evaluation_strategy="epoch" if val_dataset else "no",
            save_strategy="epoch",
            learning_rate=self.learning_rate,
            weight_decay=0.01,
            logging_dir="./logs",
            logging_steps=10,
            save_total_limit=3,
            load_best_model_at_end=True if val_dataset else False,
            fp16=torch.cuda.is_available(),
            push_to_hub=False,
        )

        self.trainer = Trainer(
            model=self.model,
            args=self.training_args,
            train_dataset=self.train_dataset,
            eval_dataset=self.val_dataset,
            tokenizer=self.tokenizer,
        )

    def train(self):
        """
        Запуск процесса обучения модели.
        """
        self.trainer.train()

    def evaluate(self):
        """
        Оценка модели на валидационном датасете.
        """
        if self.val_dataset is not None:
            return self.trainer.evaluate()
        else:
            raise ValueError("Валидационный датасет отсутствует.")

    def save_model(self, path: str):
        """
        Сохранение обученной модели и токенизатора.
        """
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
