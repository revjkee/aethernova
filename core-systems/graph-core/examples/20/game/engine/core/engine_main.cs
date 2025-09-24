using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace TeslaAI.Engine.Core
{
    /// <summary>
    /// Основной класс игрового движка Tesla AI.
    /// Отвечает за инициализацию, игровой цикл и управление состоянием.
    /// </summary>
    public class EngineMain
    {
        private bool isRunning;
        private readonly List<ISystem> systems;
        private Stopwatch stopwatch;
        private double deltaTime;

        public EngineMain()
        {
            systems = new List<ISystem>();
            stopwatch = new Stopwatch();
            isRunning = false;
            deltaTime = 0.0;
        }

        /// <summary>
        /// Добавить систему (например, рендеринг, физика, ввод)
        /// </summary>
        /// <param name="system">Система, реализующая интерфейс ISystem</param>
        public void AddSystem(ISystem system)
        {
            systems.Add(system);
        }

        /// <summary>
        /// Запустить основной игровой цикл
        /// </summary>
        public void Run()
        {
            Initialize();

            isRunning = true;
            stopwatch.Start();

            while (isRunning)
            {
                var elapsed = stopwatch.Elapsed.TotalSeconds;
                stopwatch.Restart();

                deltaTime = elapsed;

                Update(deltaTime);
                Render();

                // Ограничение FPS (например, 60 FPS)
                int targetFrameTimeMs = 16;
                var frameTimeMs = (int)(deltaTime * 1000);
                if (frameTimeMs < targetFrameTimeMs)
                {
                    System.Threading.Thread.Sleep(targetFrameTimeMs - frameTimeMs);
                }
            }

            Shutdown();
        }

        private void Initialize()
        {
            foreach (var system in systems)
            {
                system.Initialize();
            }
        }

        private void Update(double deltaTime)
        {
            foreach (var system in systems)
            {
                system.Update(deltaTime);
            }
        }

        private void Render()
        {
            foreach (var system in systems)
            {
                system.Render();
            }
        }

        /// <summary>
        /// Остановить игровой цикл
        /// </summary>
        public void Stop()
        {
            isRunning = false;
        }

        private void Shutdown()
        {
            foreach (var system in systems)
            {
                system.Shutdown();
            }
        }
    }

    /// <summary>
    /// Интерфейс для систем игрового движка
    /// </summary>
    public interface ISystem
    {
        void Initialize();
        void Update(double deltaTime);
        void Render();
        void Shutdown();
    }
}
