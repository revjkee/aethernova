using System;
using System.Collections.Generic;
using UnityEngine;

namespace TeslaAI.Engine.Physics
{
    /// <summary>
    /// Простая физическая система для симуляции сил и столкновений.
    /// Поддерживает обработку гравитации, столкновений и интеграцию движения.
    /// </summary>
    public class PhysicsEngine : MonoBehaviour
    {
        private List<PhysicsBody> bodies = new List<PhysicsBody>();

        public Vector3 Gravity = new Vector3(0, -9.81f, 0);

        /// <summary>
        /// Регистрация физического тела в движке.
        /// </summary>
        /// <param name="body">Физическое тело</param>
        public void RegisterBody(PhysicsBody body)
        {
            if (!bodies.Contains(body))
            {
                bodies.Add(body);
            }
        }

        /// <summary>
        /// Удаление физического тела из движка.
        /// </summary>
        /// <param name="body">Физическое тело</param>
        public void UnregisterBody(PhysicsBody body)
        {
            if (bodies.Contains(body))
            {
                bodies.Remove(body);
            }
        }

        void FixedUpdate()
        {
            // Интегрируем движение с учетом гравитации и столкновений
            foreach (var body in bodies)
            {
                if (body.IsStatic) continue;

                // Применяем гравитацию
                body.Velocity += Gravity * Time.fixedDeltaTime;

                // Обновляем позицию
                body.transform.position += body.Velocity * Time.fixedDeltaTime;

                // Простейшая проверка столкновений и откат
                foreach (var other in bodies)
                {
                    if (other == body) continue;

                    if (body.Collider.bounds.Intersects(other.Collider.bounds))
                    {
                        ResolveCollision(body, other);
                    }
                }
            }
        }

        private void ResolveCollision(PhysicsBody a, PhysicsBody b)
        {
            // Простое разрешение столкновения - откат на предыдущую позицию
            a.transform.position -= a.Velocity * Time.fixedDeltaTime;
            a.Velocity = Vector3.zero;
        }
    }

    /// <summary>
    /// Компонент для физического объекта.
    /// </summary>
    [RequireComponent(typeof(Collider))]
    public class PhysicsBody : MonoBehaviour
    {
        public Vector3 Velocity;
        public bool IsStatic = false;

        public Collider Collider { get; private set; }

        void Awake()
        {
            Collider = GetComponent<Collider>();
        }
    }
}
