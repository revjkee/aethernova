using System;
using UnityEngine;

namespace TeslaAI.Engine.Input
{
    /// <summary>
    /// Обработчик ввода пользователя.
    /// Отвечает за сбор и обработку данных с клавиатуры, мыши и контроллеров.
    /// </summary>
    public class InputHandler : MonoBehaviour
    {
        public float Horizontal { get; private set; }
        public float Vertical { get; private set; }
        public bool JumpPressed { get; private set; }
        public bool FirePressed { get; private set; }

        void Update()
        {
            ReadInput();
        }

        private void ReadInput()
        {
            // Считываем оси движения
            Horizontal = Input.GetAxis("Horizontal");
            Vertical = Input.GetAxis("Vertical");

            // Считываем нажатия кнопок
            JumpPressed = Input.GetButtonDown("Jump");
            FirePressed = Input.GetButtonDown("Fire1");
        }
    }
}
