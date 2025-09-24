using System;
using System.Threading.Tasks;
using UnityEngine;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;

namespace TeslaAI.Engine.Web3
{
    /// <summary>
    /// Класс для интеграции Ethereum-кошелька в игровой движок.
    /// Поддерживает подключение, авторизацию и взаимодействие с сетью.
    /// </summary>
    public class WalletIntegration : MonoBehaviour
    {
        private Web3 web3;
        private Account account;

        // Адрес контракта и RPC узел (например, Infura)
        [SerializeField] private string rpcUrl = "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID";
        [SerializeField] private string privateKey;  // В продакшене не хранить в коде

        public bool IsConnected { get; private set; }

        void Start()
        {
            ConnectWallet();
        }

        /// <summary>
        /// Подключение кошелька по приватному ключу.
        /// </summary>
        public void ConnectWallet()
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                Debug.LogError("Private key is not set.");
                IsConnected = false;
                return;
            }

            try
            {
                account = new Account(privateKey);
                web3 = new Web3(account, rpcUrl);
                IsConnected = true;
                Debug.Log($"Wallet connected: {account.Address}");
            }
            catch (Exception ex)
            {
                Debug.LogError($"Error connecting wallet: {ex.Message}");
                IsConnected = false;
            }
        }

        /// <summary>
        /// Получить баланс кошелька в эфире.
        /// </summary>
        /// <returns>Баланс в ETH</returns>
        public async Task<decimal> GetBalanceAsync()
        {
            if (!IsConnected)
            {
                Debug.LogWarning("Wallet not connected.");
                return 0m;
            }

            var balanceWei = await web3.Eth.GetBalance.SendRequestAsync(account.Address);
            var balanceEther = Web3.Convert.FromWei(balanceWei.Value);
            return balanceEther;
        }

        /// <summary>
        /// Отправка транзакции (пример).
        /// </summary>
        public async Task<string> SendTransactionAsync(string toAddress, decimal amountEther)
        {
            if (!IsConnected)
            {
                Debug.LogWarning("Wallet not connected.");
                return null;
            }

            try
            {
                var txHash = await web3.TransactionManager.SendTransactionAsync(account.Address, toAddress, Web3.Convert.ToWei(amountEther));
                Debug.Log($"Transaction sent: {txHash}");
                return txHash;
            }
            catch (Exception ex)
            {
                Debug.LogError($"Transaction failed: {ex.Message}");
                return null;
            }
        }
    }
}
