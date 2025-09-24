using System;
using System.Collections.Generic;
using UnityEngine;

namespace TeslaAI.Engine.GameplayLogic
{
    /// <summary>
    /// Управляет логикой миссий в игровом движке Tesla AI Training Sim.
    /// Обрабатывает состояние миссий, задачи, события и прогресс игрока.
    /// </summary>
    public class MissionLogic : MonoBehaviour
    {
        public List<Mission> Missions = new List<Mission>();

        private Mission currentMission;

        void Start()
        {
            if (Missions.Count > 0)
            {
                StartMission(Missions[0]);
            }
        }

        void Update()
        {
            if (currentMission == null) return;

            currentMission.UpdateMission();

            if (currentMission.IsCompleted)
            {
                OnMissionCompleted(currentMission);
                int nextIndex = Missions.IndexOf(currentMission) + 1;
                if (nextIndex < Missions.Count)
                {
                    StartMission(Missions[nextIndex]);
                }
                else
                {
                    Debug.Log("Все миссии завершены.");
                    currentMission = null;
                }
            }
        }

        private void StartMission(Mission mission)
        {
            currentMission = mission;
            currentMission.StartMission();
            Debug.Log($"Миссия начата: {mission.Title}");
        }

        private void OnMissionCompleted(Mission mission)
        {
            Debug.Log($"Миссия завершена: {mission.Title}");
            // Можно добавить логику наград, сохранения прогресса, вызова событий и т.д.
        }
    }

    /// <summary>
    /// Класс миссии с базовой логикой.
    /// </summary>
    [Serializable]
    public class Mission
    {
        public string Title;
        public string Description;

        public bool IsCompleted { get; private set; }

        // Пример состояния задачи (можно расширять под свои нужды)
        private int tasksCompleted = 0;
        private int totalTasks = 1;

        public void StartMission()
        {
            IsCompleted = false;
            tasksCompleted = 0;
            // Инициализация состояния миссии
        }

        public void UpdateMission()
        {
            // Проверка условий выполнения задач
            // Например, обновить tasksCompleted в зависимости от игровых событий

            if (tasksCompleted >= totalTasks)
            {
                IsCompleted = true;
            }
        }

        // Метод для отметки выполнения задачи
        public void CompleteTask()
        {
            tasksCompleted++;
            if (tasksCompleted > totalTasks)
                tasksCompleted = totalTasks;
        }
    }
}
