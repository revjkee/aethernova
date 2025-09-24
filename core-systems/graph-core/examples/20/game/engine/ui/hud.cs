using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;

namespace TeslaAI.Engine.UI
{
    /// <summary>
    /// HUD (Heads-Up Display) — отображение информации игроку.
    /// Отвечает за обновление и рендер элементов UI в игре.
    /// </summary>
    public class HUD : MonoBehaviour
    {
        [Header("UI Elements")]
        [SerializeField] private Text healthText;
        [SerializeField] private Text ammoText;
        [SerializeField] private Text objectiveText;
        [SerializeField] private Image healthBar;

        private int currentHealth;
        private int maxHealth;
        private int currentAmmo;

        void Start()
        {
            // Инициализация значений
            maxHealth = 100;
            currentHealth = maxHealth;
            currentAmmo = 30;
            UpdateHUD();
        }

        /// <summary>
        /// Обновить здоровье игрока и обновить UI
        /// </summary>
        /// <param name="health">Новое значение здоровья</param>
        public void SetHealth(int health)
        {
            currentHealth = Mathf.Clamp(health, 0, maxHealth);
            UpdateHealthUI();
        }

        /// <summary>
        /// Обновить количество патронов и UI
        /// </summary>
        /// <param name="ammo">Новое количество патронов</param>
        public void SetAmmo(int ammo)
        {
            currentAmmo = Math.Max(0, ammo);
            UpdateAmmoUI();
        }

        /// <summary>
        /// Установить текущую цель / задачу
        /// </summary>
        /// <param name="objective">Текст цели</param>
        public void SetObjective(string objective)
        {
            if (objectiveText != null)
            {
                objectiveText.text = objective;
            }
        }

        private void UpdateHUD()
        {
            UpdateHealthUI();
            UpdateAmmoUI();
        }

        private void UpdateHealthUI()
        {
            if (healthText != null)
                healthText.text = $"Health: {currentHealth}/{maxHealth}";

            if (healthBar != null)
                healthBar.fillAmount = (float)currentHealth / maxHealth;
        }

        private void UpdateAmmoUI()
        {
            if (ammoText != null)
                ammoText.text = $"Ammo: {currentAmmo}";
        }
    }
}
