// src/entities/master/master.model.ts

export interface Master {
  id: string;                  // уникальный идентификатор мастера
  name: string;                // имя мастера
  avatarUrl?: string;          // ссылка на фото
  rating: number;              // средний рейтинг, например 4.8
  reviewsCount: number;        // количество отзывов
  specialties: string[];       // специализации, например ['маникюр', 'педикюр']
  priceList: PriceItem[];      // прайс-лист услуг
  experienceYears: number;     // опыт работы в годах
  isAvailable: boolean;        // доступность для записи
  contact?: ContactInfo;       // контактные данные (телефон, email)
  description?: string;        // описание или биография
}

export interface PriceItem {
  serviceName: string;
  price: number;              // цена в копейках или рублях (согласуйте)
  durationMinutes?: number;   // длительность услуги в минутах (опционально)
}

export interface ContactInfo {
  phone?: string;
  email?: string;
  telegram?: string;
}

// Функция для создания пустого шаблона мастера

export const createEmptyMaster = (): Master => ({
  id: '',
  name: '',
  rating: 0,
  reviewsCount: 0,
  specialties: [],
  priceList: [],
  experienceYears: 0,
  isAvailable: false,
});
