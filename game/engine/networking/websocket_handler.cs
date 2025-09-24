using System;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;

namespace TeslaAI.Engine.Networking
{
    /// <summary>
    /// Обработчик WebSocket-соединений для игры.
    /// Управляет подключениями, отправкой и приёмом сообщений.
    /// </summary>
    public class WebSocketHandler : MonoBehaviour
    {
        private ClientWebSocket webSocket;
        private CancellationTokenSource cancellation;

        private readonly Queue<string> incomingMessages = new Queue<string>();
        private readonly object queueLock = new object();

        public event Action<string> OnMessageReceived;
        public event Action OnConnected;
        public event Action OnDisconnected;

        /// <summary>
        /// Подключение к WebSocket серверу.
        /// </summary>
        /// <param name="uri">URI сервера</param>
        public async Task ConnectAsync(Uri uri)
        {
            if (webSocket != null && webSocket.State == WebSocketState.Open)
            {
                Debug.LogWarning("WebSocket уже подключен.");
                return;
            }

            webSocket = new ClientWebSocket();
            cancellation = new CancellationTokenSource();

            try
            {
                await webSocket.ConnectAsync(uri, cancellation.Token);
                OnConnected?.Invoke();
                _ = ReceiveLoop();
            }
            catch (Exception ex)
            {
                Debug.LogError($"Ошибка подключения WebSocket: {ex.Message}");
            }
        }

        /// <summary>
        /// Отправка текстового сообщения через WebSocket.
        /// </summary>
        /// <param name="message">Текст сообщения</param>
        public async Task SendMessageAsync(string message)
        {
            if (webSocket == null || webSocket.State != WebSocketState.Open)
            {
                Debug.LogWarning("WebSocket не подключен.");
                return;
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(message);
            var buffer = new ArraySegment<byte>(bytes);

            try
            {
                await webSocket.SendAsync(buffer, WebSocketMessageType.Text, true, cancellation.Token);
            }
            catch (Exception ex)
            {
                Debug.LogError($"Ошибка при отправке сообщения: {ex.Message}");
            }
        }

        /// <summary>
        /// Цикл приёма сообщений.
        /// </summary>
        private async Task ReceiveLoop()
        {
            var buffer = new byte[1024 * 4];

            try
            {
                while (webSocket.State == WebSocketState.Open)
                {
                    var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellation.Token);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                        OnDisconnected?.Invoke();
                    }
                    else
                    {
                        var message = System.Text.Encoding.UTF8.GetString(buffer, 0, result.Count);
                        lock (queueLock)
                        {
                            incomingMessages.Enqueue(message);
                        }
                        OnMessageReceived?.Invoke(message);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Ожидаемое завершение
            }
            catch (Exception ex)
            {
                Debug.LogError($"Ошибка в ReceiveLoop: {ex.Message}");
                OnDisconnected?.Invoke();
            }
        }

        /// <summary>
        /// Отключение от сервера.
        /// </summary>
        public async Task DisconnectAsync()
        {
            if (webSocket == null) return;

            try
            {
                cancellation.Cancel();

                if (webSocket.State == WebSocketState.Open)
                {
                    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client disconnect", CancellationToken.None);
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"Ошибка отключения WebSocket: {ex.Message}");
            }
            finally
            {
                webSocket.Dispose();
                webSocket = null;
                OnDisconnected?.Invoke();
            }
        }

        private void OnDestroy()
        {
            cancellation?.Cancel();
            webSocket?.Dispose();
        }
    }
}
