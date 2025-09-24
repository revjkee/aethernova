import 'package:flutter/material.dart';

/// Общие компоненты для Tesla AI Mobile App

// Кнопка с кастомным стилем для приложения
class TeslaButton extends StatelessWidget {
  final String label;
  final VoidCallback onPressed;
  final Color color;

  const TeslaButton({
    Key? key,
    required this.label,
    required this.onPressed,
    this.color = const Color(0xFF1976D2), // Стандартный синий цвет
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      style: ElevatedButton.styleFrom(
        backgroundColor: color,
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        elevation: 3,
      ),
      onPressed: onPressed,
      child: Text(
        label,
        style: const TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
          color: Colors.white,
        ),
      ),
    );
  }
}

// Заголовок страницы с отступом и стилем
class TeslaPageTitle extends StatelessWidget {
  final String title;

  const TeslaPageTitle({Key? key, required this.title}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16.0),
      child: Text(
        title,
        style: const TextStyle(
          fontSize: 28,
          fontWeight: FontWeight.bold,
          color: Color(0xFF121212),
        ),
      ),
    );
  }
}
