using System.Collections.Generic;
using UnityEngine;

namespace TeslaAI.Engine.Audio
{
    /// <summary>
    /// Менеджер звуковых эффектов и музыки.
    /// Отвечает за проигрывание, управление громкостью и стоп звуков.
    /// </summary>
    public class SoundManager : MonoBehaviour
    {
        public static SoundManager Instance { get; private set; }

        [SerializeField] private AudioSource musicSource;
        [SerializeField] private AudioSource sfxSource;

        private Dictionary<string, AudioClip> audioClips = new Dictionary<string, AudioClip>();

        void Awake()
        {
            if (Instance == null)
            {
                Instance = this;
                DontDestroyOnLoad(gameObject);
            }
            else
            {
                Destroy(gameObject);
            }
        }

        /// <summary>
        /// Регистрация аудиоклипа по имени.
        /// </summary>
        /// <param name="name">Имя звука</param>
        /// <param name="clip">Аудиоклип</param>
        public void RegisterClip(string name, AudioClip clip)
        {
            if (!audioClips.ContainsKey(name))
            {
                audioClips.Add(name, clip);
            }
        }

        /// <summary>
        /// Проигрывание звукового эффекта.
        /// </summary>
        /// <param name="name">Имя звука</param>
        public void PlaySFX(string name)
        {
            if (audioClips.TryGetValue(name, out AudioClip clip))
            {
                sfxSource.PlayOneShot(clip);
            }
            else
            {
                Debug.LogWarning($"SoundManager: Звук '{name}' не найден.");
            }
        }

        /// <summary>
        /// Запуск фоновой музыки.
        /// </summary>
        /// <param name="name">Имя музыки</param>
        /// <param name="loop">Зацикливание</param>
        public void PlayMusic(string name, bool loop = true)
        {
            if (audioClips.TryGetValue(name, out AudioClip clip))
            {
                musicSource.clip = clip;
                musicSource.loop = loop;
                musicSource.Play();
            }
            else
            {
                Debug.LogWarning($"SoundManager: Музыка '{name}' не найдена.");
            }
        }

        /// <summary>
        /// Остановить музыку.
        /// </summary>
        public void StopMusic()
        {
            musicSource.Stop();
        }

        /// <summary>
        /// Установить громкость звуковых эффектов.
        /// </summary>
        /// <param name="volume">Громкость от 0 до 1</param>
        public void SetSFXVolume(float volume)
        {
            sfxSource.volume = Mathf.Clamp01(volume);
        }

        /// <summary>
        /// Установить громкость музыки.
        /// </summary>
        /// <param name="volume">Громкость от 0 до 1</param>
        public void SetMusicVolume(float volume)
        {
            musicSource.volume = Mathf.Clamp01(volume);
        }
    }
}
