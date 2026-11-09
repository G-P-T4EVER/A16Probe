import SwiftUI
import OSLog

@MainActor
final class DiagnosticModel: ObservableObject {
    @Published var running = false
    @Published var report: String = ""
    @Published var file: URL?
    @Published var failure: String?

    func run(exploitTrial: Bool = false) {
        guard !running else { return }
        running = true
        report = ""
        file = nil
        failure = nil
        Task {
            defer { running = false }
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    try DiagnosticRunner.run(exploitTrial: exploitTrial)
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
    @State private var confirmingExploitTrial = false

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
                    Button { model.run() } label: {
                        Label(model.running ? "Диагностика…" : "Запустить диагностику", systemImage: "stethoscope")
                    }
                    .disabled(model.running)
                    if model.running { ProgressView() }
                }
                Section("Проверка sandbox escape · экспериментально") {
                    Text("Два независимых способа запроса sandbox extension через ContainerManager: geod (class 12) и прямой запрос MobileGestalt (class 13). Это настоящие попытки получить разрешение, а не поиск символов.")
                        .font(.footnote)
                    Text("Тест не меняет системные файлы и не записывает ни одного байта. Используются приватные API: на неподдерживаемой бете приложение может закрыться.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button {
                        confirmingExploitTrial = true
                    } label: {
                        Label("Проверить sandbox escape", systemImage: "lock.open")
                    }
                    .disabled(model.running)
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
            .alert("Экспериментальная проверка", isPresented: $confirmingExploitTrial) {
                Button("Отмена", role: .cancel) {}
                Button("Запустить", role: .destructive) {
                    model.run(exploitTrial: true)
                }
            } message: {
                Text("Будут вызваны приватные функции ContainerManager. Системные файлы не изменяются, но приложение может завершиться аварийно.")
            }
        }
    }
}
