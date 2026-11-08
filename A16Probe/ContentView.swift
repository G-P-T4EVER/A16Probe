import SwiftUI
import OSLog

@MainActor
final class DiagnosticModel: ObservableObject {
    @Published var running = false
    @Published var report: String = ""
    @Published var file: URL?
    @Published var failure: String?

    func run() {
        guard !running else { return }
        running = true
        report = ""
        file = nil
        failure = nil
        Task {
            defer { running = false }
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    try DiagnosticRunner.run()
                }.value
                report = result.text
                file = result.file
            } catch {
                failure = error.localizedDescription
                Logger(subsystem: "org.a16probe.research", category: "diagnostics")
                    .error("Diagnostic run or report persistence failed: \(error.localizedDescription, privacy: .private)")
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var model = DiagnosticModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Цель исследования") {
                    Text("iPhone 14 Pro Max · A16")
                    Text("iOS 27.3 beta 1 — целевая конфигурация, ещё не подтверждённая тестом на устройстве.")
                        .font(.footnote)
                }
                Section("Безопасная диагностика") {
                    Text("Проверка модели, версии ОС, публичных API и видимости символов ContainerManager в уже загруженных библиотеках.")
                    Text("Приватные функции не вызываются. Наличие символов не доказывает уязвимость. Логи сохраняются только внутри приложения; последние 20 отчётов остаются на устройстве.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button(action: model.run) {
                        Label(model.running ? "Диагностика…" : "Запустить диагностику", systemImage: "stethoscope")
                    }
                    .disabled(model.running)
                    if model.running { ProgressView() }
                }
                if let failure = model.failure {
                    Section("Ошибка") { Text(failure).foregroundStyle(.red).textSelection(.enabled) }
                }
                if let file = model.file {
                    Section("Отчёт сохранён") {
                        ShareLink(item: file) { Label("Экспорт JSON", systemImage: "square.and.arrow.up") }
                        Text("Отчёт содержит модель, сборку ОС и сведения о runtime. Просмотрите его перед отправкой.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if !model.report.isEmpty {
                    Section("Подробный журнал") {
                        Text(model.report).font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("A16Probe")
        }
    }
}
