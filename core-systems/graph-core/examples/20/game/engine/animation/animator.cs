using UnityEngine;

namespace TeslaAI.Engine.Animation
{
    /// <summary>
    /// Управляет анимациями персонажа.
    /// Отвечает за переключение состояний и плавность переходов.
    /// </summary>
    [RequireComponent(typeof(Animator))]
    public class AnimatorController : MonoBehaviour
    {
        private Animator animator;

        private static readonly int IdleHash = Animator.StringToHash("Idle");
        private static readonly int RunHash = Animator.StringToHash("Run");
        private static readonly int JumpHash = Animator.StringToHash("Jump");
        private static readonly int AttackHash = Animator.StringToHash("Attack");

        void Awake()
        {
            animator = GetComponent<Animator>();
        }

        /// <summary>
        /// Переключение на анимацию Idle.
        /// </summary>
        public void PlayIdle()
        {
            animator.CrossFade(IdleHash, 0.1f);
        }

        /// <summary>
        /// Переключение на анимацию бега.
        /// </summary>
        public void PlayRun()
        {
            animator.CrossFade(RunHash, 0.1f);
        }

        /// <summary>
        /// Запуск анимации прыжка.
        /// </summary>
        public void PlayJump()
        {
            animator.CrossFade(JumpHash, 0.1f);
        }

        /// <summary>
        /// Запуск анимации атаки.
        /// </summary>
        public void PlayAttack()
        {
            animator.CrossFade(AttackHash, 0.1f);
        }
    }
}
