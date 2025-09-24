import SwiftUI
import Combine

// MARK: - Общие UI модификаторы

public extension View {

    /// Стиль скелетон-загрузки
    func skeleton(isVisible: Bool = true, cornerRadius: CGFloat = 6) -> some View {
        modifier(SkeletonModifier(isVisible: isVisible, cornerRadius: cornerRadius))
    }

    /// Подсветка безопасного интента
    func aiIntentPulse(active: Bool = true) -> some View {
        modifier(AIPulseModifier(isActive: active))
    }

    /// Блокировка экрана при ZT-защите
    func zeroTrustBlur(_ isActive: Bool = true) -> some View {
        self.blur(radius: isActive ? 8.0 : 0)
            .overlay(
                isActive ? Color.black.opacity(0.4) : Color.clear
            )
            .animation(.easeInOut, value: isActive)
    }

    /// Применить фон на основе текущей темы
    func adaptiveBackground() -> some View {
        self.background(Color.adaptiveBackground)
    }

    /// Обертка ошибки
    func errorBanner(_ message: String?, isVisible: Bool) -> some View {
        modifier(ErrorBannerModifier(message: message, isVisible: isVisible))
    }

    /// Стиль интерактивной кнопки
    func intentButtonStyle(enabled: Bool = true) -> some View {
        self
            .opacity(enabled ? 1.0 : 0.4)
            .animation(.easeInOut, value: enabled)
            .disabled(!enabled)
    }

    /// Применение общего паддинга и безопасной зоны
    func paddedContainer() -> some View {
        self
            .padding()
            .background(Color.backgroundElevated)
            .cornerRadius(16)
            .shadow(radius: 4)
            .padding(.horizontal)
    }

    /// Безопасная область и системные inset-ы
    func safeAreaInsets() -> some View {
        self
            .edgesIgnoringSafeArea(.bottom)
            .padding(.top, UIApplication.shared.windows.first?.safeAreaInsets.top ?? 0)
    }
}

// MARK: - Skeleton Modifier
struct SkeletonModifier: ViewModifier {
    var isVisible: Bool
    var cornerRadius: CGFloat

    @State private var animate = false

    func body(content: Content) -> some View {
        ZStack {
            content.opacity(isVisible ? 0 : 1)
            if isVisible {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .fill(
                        LinearGradient(
                            gradient: Gradient(colors: [Color.gray.opacity(0.3), Color.gray.opacity(0.1), Color.gray.opacity(0.3)]),
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .shimmering(active: animate)
                    .onAppear { animate = true }
            }
        }
    }
}

// MARK: - AI Pulse Modifier
struct AIPulseModifier: ViewModifier {
    var isActive: Bool

    @State private var pulse = false

    func body(content: Content) -> some View {
        content
            .scaleEffect(pulse ? 1.02 : 1.0)
            .shadow(color: Color.accentAI.opacity(pulse ? 0.3 : 0.1), radius: 12)
            .animation(.easeInOut(duration: 1).repeatForever(autoreverses: true), value: pulse)
            .onAppear { if isActive { pulse = true } }
    }
}

// MARK: - Error Banner Modifier
struct ErrorBannerModifier: ViewModifier {
    let message: String?
    let isVisible: Bool

    func body(content: Content) -> some View {
        VStack(spacing: 0) {
            if isVisible, let message = message {
                Text(message)
                    .foregroundColor(.white)
                    .font(.subheadline)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.error)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .animation(.easeInOut, value: isVisible)
            }
            content
        }
    }
}

// MARK: - Shimmer Effect
extension View {
    func shimmering(active: Bool) -> some View {
        self
            .modifier(ShimmerModifier(active: active))
    }
}

struct ShimmerModifier: ViewModifier {
    var active: Bool
    @State private var phase: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .overlay(
                GeometryReader { geometry in
                    Rectangle()
                        .fill(
                            LinearGradient(
                                gradient: Gradient(colors: [Color.clear, Color.white.opacity(0.4), Color.clear]),
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .rotationEffect(.degrees(30))
                        .offset(x: phase)
                        .frame(width: geometry.size.width * 1.5)
                }
                .clipped()
                .opacity(active ? 1 : 0)
            )
            .onAppear {
                withAnimation(.linear(duration: 1.5).repeatForever(autoreverses: false)) {
                    phase = 300
                }
            }
    }
}
