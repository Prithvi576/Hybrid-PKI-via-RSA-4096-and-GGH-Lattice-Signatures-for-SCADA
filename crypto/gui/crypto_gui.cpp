#include "crypto_api.hpp"

#include <windows.h>
#include <commctrl.h>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

namespace {

constexpr int kRsaGenerate = 101;
constexpr int kGghGenerate = 102;
constexpr int kSign = 103;
constexpr int kVerify = 104;
constexpr int kModifyCommand = 105;
constexpr int kModifyTimestamp = 106;
constexpr int kModifySequence = 107;
constexpr int kCorruptRsa = 108;
constexpr int kCorruptGgh = 109;

constexpr COLORREF kBackground = RGB(12, 18, 28);
constexpr COLORREF kCard = RGB(22, 33, 48);
constexpr COLORREF kField = RGB(18, 27, 40);
constexpr COLORREF kText = RGB(229, 237, 245);
constexpr COLORREF kMuted = RGB(152, 170, 190);
constexpr COLORREF kAccent = RGB(38, 202, 173);

struct Controls {
    HWND rsa_status{};
    HWND ggh_status{};
    HWND rsa_fingerprint{};
    HWND ggh_fingerprint{};
    HWND command{};
    HWND timestamp{};
    HWND sequence{};
    HWND verification{};
    HWND signature_info{};
    HWND details{};
    HWND benchmarks{};
    HWND event_log{};
};

struct Timings {
    std::optional<std::chrono::nanoseconds> rsa_keygen;
    std::optional<std::chrono::nanoseconds> ggh_keygen;
    std::optional<hybrid_pki::OperationMeasurements> sign;
    std::optional<hybrid_pki::OperationMeasurements> verify;
};

struct AppState {
    std::unique_ptr<hybrid_pki::RSAKeyPair> rsa;
    std::unique_ptr<hybrid_pki::GGHKeyPair> ggh;
    hybrid_pki::HybridSignedCommand signed_command;
    bool has_signed_command{};
    std::uint64_t next_sequence{105};
    Timings timings;
};

Controls g_controls;
AppState g_state;
HFONT g_title_font{};
HFONT g_heading_font{};
HFONT g_body_font{};
HFONT g_mono_font{};
HBRUSH g_background_brush{};
HBRUSH g_card_brush{};
HBRUSH g_field_brush{};

std::wstring widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        return L"[encoding error]";
    }
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        output.data(), size);
    return output;
}

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::invalid_argument("command must be valid UTF-8");
    }
    std::string output(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        output.data(), size, nullptr, nullptr);
    return output;
}

void setText(HWND control, const std::string& value) { SetWindowTextW(control, widen(value).c_str()); }

std::wstring controlText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring value(static_cast<std::size_t>(length), L'\0');
    GetWindowTextW(control, value.data(), length + 1);
    return value;
}

std::string nowUtc() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << now.wYear << '-' << std::setw(2) << now.wMonth << '-'
           << std::setw(2) << now.wDay << 'T' << std::setw(2) << now.wHour << ':' << std::setw(2)
           << now.wMinute << ':' << std::setw(2) << now.wSecond << 'Z';
    return output.str();
}

std::string clockTime() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    std::ostringstream output;
    output << std::setfill('0') << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute << ':'
           << std::setw(2) << now.wSecond;
    return output.str();
}

std::string durationText(const std::chrono::nanoseconds duration) {
    const auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    std::ostringstream output;
    if (microseconds >= 1000) {
        output << std::fixed << std::setprecision(2) << (static_cast<double>(microseconds) / 1000.0) << " ms";
    } else {
        output << microseconds << " us";
    }
    return output.str();
}

void appendLog(const std::string& line) {
    const std::wstring entry = widen("[" + clockTime() + "] " + line + "\r\n");
    const int end = GetWindowTextLengthW(g_controls.event_log);
    SendMessageW(g_controls.event_log, EM_SETSEL, end, end);
    SendMessageW(g_controls.event_log, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(entry.c_str()));
    SendMessageW(g_controls.event_log, EM_SCROLLCARET, 0, 0);
}

void showError(HWND window, const std::string& message) {
    MessageBoxW(window, widen(message).c_str(), L"Cryptographic operation", MB_OK | MB_ICONERROR);
}

void resetVerification() {
    setText(g_controls.verification,
            "RSA verification: PENDING\r\nGGH verification: PENDING\r\nOverall result: PENDING");
}

void updateDetails() {
    std::ostringstream details;
    details << "Active GGH configuration\r\n" << hybrid_pki::gghConfiguration()
            << "\r\n\r\nKey visibility\r\nPrivate key material is never rendered or logged.\r\n\r\n"
            << "Canonical message\r\n";
    if (g_state.has_signed_command) {
        const auto canonical = hybrid_pki::canonicalize(g_state.signed_command.envelope);
        details << canonical.size() << " bytes, length-delimited UTF-8 fields\r\n"
                << "COMMAND=" << g_state.signed_command.envelope.command << "\r\n"
                << "TIMESTAMP=" << g_state.signed_command.envelope.timestamp_utc << "\r\n"
                << "SEQUENCE=" << g_state.signed_command.envelope.sequence;
    } else {
        details << "Created on SIGN COMMAND.";
    }
    setText(g_controls.details, details.str());
}

void updateBenchmarks() {
    const auto one = [](const std::optional<std::chrono::nanoseconds>& duration) {
        return duration ? durationText(*duration) : std::string("not run");
    };
    const auto part = [](const std::optional<hybrid_pki::OperationMeasurements>& metrics,
                         const std::chrono::nanoseconds hybrid_pki::OperationMeasurements::*member) {
        return metrics ? durationText((*metrics).*member) : std::string("not run");
    };
    std::ostringstream benchmark;
    benchmark << "RSA key generation: " << one(g_state.timings.rsa_keygen) << "\r\n"
              << "GGH key generation: " << one(g_state.timings.ggh_keygen) << "\r\n"
              << "RSA signing: " << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::rsa) << "\r\n"
              << "GGH signing: " << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::ggh) << "\r\n"
              << "Hybrid signing: " << part(g_state.timings.sign, &hybrid_pki::OperationMeasurements::hybrid) << "\r\n"
              << "RSA verification: " << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::rsa) << "\r\n"
              << "GGH verification: " << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::ggh) << "\r\n"
              << "Hybrid verification: "
              << part(g_state.timings.verify, &hybrid_pki::OperationMeasurements::hybrid);
    setText(g_controls.benchmarks, benchmark.str());
}

void updateSignatureInfo() {
    if (!g_state.has_signed_command) {
        setText(g_controls.signature_info, "Signature information\r\nNo hybrid command has been signed.");
        return;
    }
    const auto rsa_size = g_state.signed_command.rsa_signature.size();
    const auto ggh_size = hybrid_pki::gghSignatureSize(g_state.signed_command.ggh_signature);
    std::ostringstream information;
    information << "Signature information\r\nRSA signature: " << rsa_size << " bytes\r\n"
                << "GGH signature: " << ggh_size << " bytes\r\n"
                << "Hybrid total: " << (rsa_size + ggh_size) << " bytes\r\n"
                << "RSA fingerprint: " << g_state.rsa->public_fingerprint.substr(0, 16) << "...\r\n"
                << "GGH fingerprint: " << g_state.ggh->public_fingerprint.substr(0, 16) << "...";
    setText(g_controls.signature_info, information.str());
}

bool requireSigned(HWND window) {
    if (g_state.has_signed_command) {
        return true;
    }
    showError(window, "Sign a command before using tampering controls.");
    return false;
}

void generateRsa(HWND window) {
    try {
        appendLog("RSA-4096 key generation started");
        const auto start = std::chrono::steady_clock::now();
        auto key = std::make_unique<hybrid_pki::RSAKeyPair>(hybrid_pki::generateRSAKeyPair());
        g_state.timings.rsa_keygen = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start);
        g_state.rsa = std::move(key);
        setText(g_controls.rsa_status, "RSA-4096 status: GENERATED (RSA-PSS/SHA-256)");
        setText(g_controls.rsa_fingerprint, "Public fingerprint: " + g_state.rsa->public_fingerprint);
        appendLog("RSA-4096 key generated in " + durationText(*g_state.timings.rsa_keygen));
        updateBenchmarks();
    } catch (const std::exception& error) {
        appendLog("RSA key generation failed");
        showError(window, error.what());
    }
}

void generateGgh(HWND window) {
    try {
        appendLog("GGH key generation started");
        const auto start = std::chrono::steady_clock::now();
        auto key = std::make_unique<hybrid_pki::GGHKeyPair>(hybrid_pki::generateGGHKeyPair());
        g_state.timings.ggh_keygen = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start);
        g_state.ggh = std::move(key);
        setText(g_controls.ggh_status, "GGH status: GENERATED (EDUCATIONAL REFERENCE)");
        setText(g_controls.ggh_fingerprint, "Public fingerprint: " + g_state.ggh->public_fingerprint);
        appendLog("GGH key generated in " + durationText(*g_state.timings.ggh_keygen));
        updateBenchmarks();
        updateDetails();
    } catch (const std::exception& error) {
        appendLog("GGH key generation failed");
        showError(window, error.what());
    }
}

void signCommand(HWND window) {
    if (!g_state.rsa || !g_state.ggh) {
        showError(window, "Generate both an RSA-4096 key and a GGH key before signing.");
        return;
    }
    try {
        hybrid_pki::CommandEnvelope envelope{narrow(controlText(g_controls.command)), nowUtc(),
                                             g_state.next_sequence++};
        setText(g_controls.timestamp, "Timestamp: " + envelope.timestamp_utc + " (auto)");
        setText(g_controls.sequence, "Sequence / nonce: " + std::to_string(envelope.sequence) + " (auto)");
        appendLog("Command entered; canonical message generated");
        auto result = hybrid_pki::hybridSign(envelope, *g_state.rsa, *g_state.ggh);
        g_state.signed_command = std::move(result.signed_command);
        g_state.timings.sign = result.measurements;
        g_state.has_signed_command = true;
        appendLog("RSA signing completed in " + durationText(result.measurements.rsa));
        appendLog("GGH signing completed in " + durationText(result.measurements.ggh));
        appendLog("Hybrid signature created in " + durationText(result.measurements.hybrid));
        updateSignatureInfo();
        updateDetails();
        updateBenchmarks();
        resetVerification();
    } catch (const std::exception& error) {
        appendLog("Signing failed");
        showError(window, error.what());
    }
}

void verifyCommand(HWND window) {
    if (!requireSigned(window) || !g_state.rsa || !g_state.ggh) {
        return;
    }
    const auto result = hybrid_pki::hybridVerify(g_state.signed_command, *g_state.rsa, *g_state.ggh);
    g_state.timings.verify = result.measurements;
    const std::string rsa = result.rsa_valid ? "PASS" : "FAIL";
    const std::string ggh = result.ggh_valid ? "PASS" : "FAIL";
    const std::string overall = result.overall_valid ? "VALID" : "INVALID";
    setText(g_controls.verification, "RSA verification: " + rsa + "\r\nGGH verification: " + ggh +
                                         "\r\nOverall result: " + overall);
    appendLog("RSA verification " + rsa);
    appendLog("GGH verification " + ggh);
    appendLog("Overall verification " + overall);
    updateBenchmarks();
}

void tamper(HWND window, const int operation) {
    if (!requireSigned(window)) {
        return;
    }
    switch (operation) {
        case kModifyCommand:
            g_state.signed_command.envelope.command =
                g_state.signed_command.envelope.command == "OPEN_VALVE" ? "CLOSE_VALVE"
                                                                        : "OPEN_VALVE";
            setText(g_controls.command, g_state.signed_command.envelope.command);
            appendLog("Command modified; previous signatures retained");
            break;
        case kModifyTimestamp:
            g_state.signed_command.envelope.timestamp_utc = "1970-01-01T00:00:00Z";
            setText(g_controls.timestamp, "Timestamp: 1970-01-01T00:00:00Z (modified)");
            appendLog("Timestamp modified; previous signatures retained");
            break;
        case kModifySequence:
            ++g_state.signed_command.envelope.sequence;
            setText(g_controls.sequence, "Sequence / nonce: " +
                                             std::to_string(g_state.signed_command.envelope.sequence) +
                                             " (modified)");
            appendLog("Sequence modified; previous signatures retained");
            break;
        case kCorruptRsa:
            if (!g_state.signed_command.rsa_signature.empty()) {
                g_state.signed_command.rsa_signature.front() ^= 0x01U;
            }
            appendLog("RSA signature corrupted");
            break;
        case kCorruptGgh:
            if (!g_state.signed_command.ggh_signature.lattice_point.empty()) {
                ++g_state.signed_command.ggh_signature.lattice_point.front();
            }
            appendLog("GGH signature corrupted");
            break;
        default:
            return;
    }
    resetVerification();
    updateDetails();
}

HWND makeControl(const wchar_t* type, const wchar_t* text, DWORD style, int id, HWND parent, HFONT font) {
    HWND control = CreateWindowExW(0, type, text, style, 0, 0, 0, 0, parent,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   GetModuleHandleW(nullptr), nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return control;
}

void move(HWND control, int x, int y, int width, int height) {
    SetWindowPos(control, nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

void layout(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    const int margin = 22;
    const int left_width = (width - margin * 3) * 42 / 100;
    const int right_x = margin * 2 + left_width;
    const int right_width = width - right_x - margin;
    const int header = 94;
    const int row = 30;

    move(g_controls.rsa_status, margin + 14, header + 32, left_width - 28, 24);
    move(g_controls.rsa_fingerprint, margin + 14, header + 58, left_width - 28, 22);
    move(GetDlgItem(window, kRsaGenerate), margin + 14, header + 84, left_width - 28, 32);
    move(g_controls.ggh_status, margin + 14, header + 138, left_width - 28, 24);
    move(g_controls.ggh_fingerprint, margin + 14, header + 164, left_width - 28, 22);
    move(GetDlgItem(window, kGghGenerate), margin + 14, header + 190, left_width - 28, 32);

    move(g_controls.command, right_x + 14, header + 34, right_width - 28, row);
    move(g_controls.timestamp, right_x + 14, header + 70, right_width - 28, 22);
    move(g_controls.sequence, right_x + 14, header + 96, right_width - 28, 22);
    const int action_width = (right_width - 42) / 2;
    move(GetDlgItem(window, kSign), right_x + 14, header + 128, action_width, 34);
    move(GetDlgItem(window, kVerify), right_x + 28 + action_width, header + 128, action_width, 34);
    move(g_controls.verification, right_x + 14, header + 176, right_width - 28, 70);

    const int middle_y = header + 262;
    const int available = std::max(120, height - middle_y - margin);
    const int left_bottom = available / 2;
    move(g_controls.signature_info, margin + 14, middle_y + 28, left_width - 28, 128);
    move(g_controls.details, margin + 14, middle_y + 170, left_width - 28, std::max(86, left_bottom - 170));
    move(g_controls.benchmarks, right_x + 14, middle_y + 28, right_width - 28, 162);
    move(g_controls.event_log, right_x + 14, middle_y + 204, right_width - 28, std::max(80, available - 204));

    const int button_y = height - 42;
    const int tamper_width = std::max(104, (width - margin * 2 - 32) / 5);
    move(GetDlgItem(window, kModifyCommand), margin, button_y, tamper_width, 28);
    move(GetDlgItem(window, kModifyTimestamp), margin + (tamper_width + 8), button_y, tamper_width, 28);
    move(GetDlgItem(window, kModifySequence), margin + 2 * (tamper_width + 8), button_y, tamper_width, 28);
    move(GetDlgItem(window, kCorruptRsa), margin + 3 * (tamper_width + 8), button_y, tamper_width, 28);
    move(GetDlgItem(window, kCorruptGgh), margin + 4 * (tamper_width + 8), button_y, tamper_width, 28);
}

LRESULT CALLBACK windowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
        case WM_CREATE: {
            g_title_font = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                       DEFAULT_PITCH, L"Segoe UI");
            g_heading_font = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                         DEFAULT_PITCH, L"Segoe UI");
            g_body_font = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                      DEFAULT_PITCH, L"Segoe UI");
            g_mono_font = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                      FIXED_PITCH, L"Cascadia Mono");
            g_background_brush = CreateSolidBrush(kBackground);
            g_card_brush = CreateSolidBrush(kCard);
            g_field_brush = CreateSolidBrush(kField);

            makeControl(L"STATIC", L"HYBRID PKI \u2014 SCADA CRYPTOGRAPHY", WS_CHILD | WS_VISIBLE, 0, window,
                        g_title_font);
            makeControl(L"STATIC", L"RSA-4096 + GGH Lattice Signature Demonstration", WS_CHILD | WS_VISIBLE, 0,
                        window, g_body_font);
            makeControl(L"STATIC", L"KEY MANAGEMENT", WS_CHILD | WS_VISIBLE, 0, window, g_heading_font);
            makeControl(L"STATIC", L"COMMAND PANEL", WS_CHILD | WS_VISIBLE, 0, window, g_heading_font);
            makeControl(L"STATIC", L"PIPELINE: COMMAND -> CANONICAL MESSAGE -> RSA-4096 + GGH -> HYBRID", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);

            g_controls.rsa_status = makeControl(L"STATIC", L"RSA-4096 status: NOT GENERATED", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            g_controls.rsa_fingerprint = makeControl(L"STATIC", L"Public fingerprint: unavailable", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            makeControl(L"BUTTON", L"GENERATE RSA-4096 KEY", WS_CHILD | WS_VISIBLE | BS_FLAT, kRsaGenerate, window, g_body_font);
            g_controls.ggh_status = makeControl(L"STATIC", L"GGH status: NOT GENERATED", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            g_controls.ggh_fingerprint = makeControl(L"STATIC", L"Public fingerprint: unavailable", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            makeControl(L"BUTTON", L"GENERATE GGH KEY", WS_CHILD | WS_VISIBLE | BS_FLAT, kGghGenerate, window, g_body_font);

            g_controls.command = makeControl(L"EDIT", L"OPEN_VALVE", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, window, g_body_font);
            g_controls.timestamp = makeControl(L"STATIC", L"Timestamp: AUTO ON SIGN", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            g_controls.sequence = makeControl(L"STATIC", L"Sequence / nonce: AUTO ON SIGN", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            makeControl(L"BUTTON", L"SIGN COMMAND", WS_CHILD | WS_VISIBLE | BS_FLAT, kSign, window, g_body_font);
            makeControl(L"BUTTON", L"VERIFY COMMAND", WS_CHILD | WS_VISIBLE | BS_FLAT, kVerify, window, g_body_font);
            g_controls.verification = makeControl(L"STATIC", L"RSA verification: PENDING\r\nGGH verification: PENDING\r\nOverall result: PENDING", WS_CHILD | WS_VISIBLE, 0, window, g_heading_font);

            g_controls.signature_info = makeControl(L"STATIC", L"Signature information\r\nNo hybrid command has been signed.", WS_CHILD | WS_VISIBLE, 0, window, g_body_font);
            g_controls.details = makeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 0, window, g_mono_font);
            g_controls.benchmarks = makeControl(L"STATIC", L"BENCHMARKS", WS_CHILD | WS_VISIBLE, 0, window, g_mono_font);
            g_controls.event_log = makeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL, 0, window, g_mono_font);
            makeControl(L"BUTTON", L"MODIFY COMMAND", WS_CHILD | WS_VISIBLE | BS_FLAT, kModifyCommand, window, g_body_font);
            makeControl(L"BUTTON", L"MODIFY TIMESTAMP", WS_CHILD | WS_VISIBLE | BS_FLAT, kModifyTimestamp, window, g_body_font);
            makeControl(L"BUTTON", L"MODIFY SEQUENCE", WS_CHILD | WS_VISIBLE | BS_FLAT, kModifySequence, window, g_body_font);
            makeControl(L"BUTTON", L"CORRUPT RSA SIGNATURE", WS_CHILD | WS_VISIBLE | BS_FLAT, kCorruptRsa, window, g_body_font);
            makeControl(L"BUTTON", L"CORRUPT GGH SIGNATURE", WS_CHILD | WS_VISIBLE | BS_FLAT, kCorruptGgh, window, g_body_font);
            updateDetails();
            updateBenchmarks();
            appendLog("Dashboard ready; generate both keys to begin.");
            return 0;
        }
        case WM_SIZE:
            layout(window);
            return 0;
        case WM_COMMAND:
            if (HIWORD(wparam) == BN_CLICKED) {
                switch (LOWORD(wparam)) {
                    case kRsaGenerate: generateRsa(window); break;
                    case kGghGenerate: generateGgh(window); break;
                    case kSign: signCommand(window); break;
                    case kVerify: verifyCommand(window); break;
                    case kModifyCommand:
                    case kModifyTimestamp:
                    case kModifySequence:
                    case kCorruptRsa:
                    case kCorruptGgh: tamper(window, LOWORD(wparam)); break;
                    default: break;
                }
            }
            return 0;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, kText);
            SetBkColor(dc, kBackground);
            return reinterpret_cast<LRESULT>(g_background_brush);
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, kText);
            SetBkColor(dc, kField);
            return reinterpret_cast<LRESULT>(g_field_brush);
        }
        case WM_ERASEBKGND: {
            RECT rect{};
            GetClientRect(window, &rect);
            FillRect(reinterpret_cast<HDC>(wparam), &rect, g_background_brush);
            return 1;
        }
        case WM_DESTROY:
            DeleteObject(g_title_font);
            DeleteObject(g_heading_font);
            DeleteObject(g_body_font);
            DeleteObject(g_mono_font);
            DeleteObject(g_background_brush);
            DeleteObject(g_card_brush);
            DeleteObject(g_field_brush);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, wparam, lparam);
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int command_show) {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    const wchar_t* class_name = L"HybridPkiScadaCryptoGui";
    WNDCLASSW window_class{};
    window_class.hInstance = instance;
    window_class.lpszClassName = class_name;
    window_class.lpfnWndProc = windowProcedure;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hbrBackground = CreateSolidBrush(kBackground);
    RegisterClassW(&window_class);

    HWND window = CreateWindowExW(0, class_name, L"HYBRID PKI - SCADA CRYPTOGRAPHY",
                                  WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 1180, 780,
                                  nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        return 1;
    }
    ShowWindow(window, command_show);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
