//! Windows system tray implementation using raw Win32 API.
//!
//! Replaces tray-item and winreg crates with direct windows-sys calls.

use std::sync::mpsc;

/// Tray menu messages
#[derive(Debug, Clone)]
pub enum TrayMessage {
    Quit,
    #[allow(dead_code)]
    Minimize,
    #[allow(dead_code)]
    BringToFront,
}

// Shell notification constants
const NIM_ADD: u32 = 0x00000000;
#[allow(dead_code)]
const NIM_MODIFY: u32 = 0x00000001;
const NIM_DELETE: u32 = 0x00000002;
const NIF_MESSAGE: u32 = 0x00000001;
const NIF_ICON: u32 = 0x00000002;
const NIF_TIP: u32 = 0x00000004;

// Window message constants
const WM_USER: u32 = 0x0400;
const WM_TRAYICON: u32 = WM_USER + 1;
const WM_COMMAND: u32 = 0x0111;
const WM_DESTROY: u32 = 0x0002;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_LBUTTONDBLCLK: u32 = 0x0203;

// Menu constants
const MF_STRING: u32 = 0x00000000;
const MF_SEPARATOR: u32 = 0x00000800;
const TPM_RIGHTALIGN: u32 = 0x0008;
const TPM_BOTTOMALIGN: u32 = 0x0020;
const TPM_NONOTIFY: u32 = 0x0080;
const TPM_RETURNCMD: u32 = 0x0100;

// Menu item IDs
const ID_BRING_TO_FRONT: u16 = 1;
const ID_MINIMIZE: u16 = 2;
const ID_QUIT: u16 = 4;

// Icon constants
const IDI_APPLICATION: *const u16 = 32512 as *const u16;

#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(dwmessage: u32, lpdata: *const NotifyIconDataW) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn CreatePopupMenu() -> isize;
    fn DestroyMenu(hmenu: isize) -> i32;
    fn AppendMenuW(hmenu: isize, uflags: u32, uidnewitem: usize, lpnewitem: *const u16) -> i32;
    fn TrackPopupMenu(
        hmenu: isize,
        uflags: u32,
        x: i32,
        y: i32,
        nreserved: i32,
        hwnd: isize,
        prcrect: *const std::ffi::c_void,
    ) -> i32;
    fn GetCursorPos(lppoint: *mut Point) -> i32;
    fn SetForegroundWindow(hwnd: isize) -> i32;
    #[allow(dead_code)]
    fn PostMessageW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> i32;
    fn LoadIconW(hinstance: isize, lpiconname: *const u16) -> isize;
    fn LoadImageW(
        hinst: isize,
        name: *const u16,
        r#type: u32,
        cx: i32,
        cy: i32,
        fuload: u32,
    ) -> isize;
    fn CreateWindowExW(
        dwexstyle: u32,
        lpclassname: *const u16,
        lpwindowname: *const u16,
        dwstyle: u32,
        x: i32,
        y: i32,
        nwidth: i32,
        nheight: i32,
        hwndparent: isize,
        hmenu: isize,
        hinstance: isize,
        lpparam: *const std::ffi::c_void,
    ) -> isize;
    fn DefWindowProcW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> isize;
    fn RegisterClassExW(lpwndclass: *const WndClassExW) -> u16;
    fn GetMessageW(lpmsg: *mut Msg, hwnd: isize, wmsgfiltermin: u32, wmsgfiltermax: u32) -> i32;
    fn TranslateMessage(lpmsg: *const Msg) -> i32;
    fn DispatchMessageW(lpmsg: *const Msg) -> isize;
    fn PostQuitMessage(nexitcode: i32);
    fn DestroyWindow(hwnd: isize) -> i32;
    fn GetModuleHandleW(lpmodulename: *const u16) -> isize;
    fn ShowWindow(hwnd: isize, ncmdshow: i32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleWindow() -> isize;
}

// ShowWindow constants
const SW_HIDE: i32 = 0;
const SW_RESTORE: i32 = 9;

#[repr(C)]
struct Point {
    x: i32,
    y: i32,
}

#[repr(C)]
struct Msg {
    hwnd: isize,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt: Point,
}

#[repr(C)]
struct WndClassExW {
    cbsize: u32,
    style: u32,
    lpfnwndproc: unsafe extern "system" fn(isize, u32, usize, isize) -> isize,
    cbclsextra: i32,
    cbwndextra: i32,
    hinstance: isize,
    hicon: isize,
    hcursor: isize,
    hbrbackground: isize,
    lpszmenuname: *const u16,
    lpszclassname: *const u16,
    hiconsm: isize,
}

#[repr(C)]
struct NotifyIconDataW {
    cbsize: u32,
    hwnd: isize,
    uid: u32,
    uflags: u32,
    ucallbackmessage: u32,
    hicon: isize,
    sztip: [u16; 128],
    dwstate: u32,
    dwstatemask: u32,
    szinfo: [u16; 256],
    u: u32,
    szinfotitle: [u16; 64],
    dwinfoflag: u32,
    guiditem: [u8; 16],
    hballoonicon: isize,
}

static TRAY_STATE: std::sync::Mutex<Option<TrayState>> = std::sync::Mutex::new(None);
static TRAY_TX: std::sync::Mutex<Option<mpsc::Sender<TrayMessage>>> = std::sync::Mutex::new(None);

struct TrayState {
    hwnd: isize,
    _thread: std::thread::JoinHandle<()>,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn show_context_menu(hwnd: isize) {
    unsafe {
        let hmenu = CreatePopupMenu();
        if hmenu == 0 {
            return;
        }

        let bring_to_front = to_wide("Bring to Front");
        let minimize = to_wide("Minimize");
        let quit = to_wide("Quit");

        AppendMenuW(
            hmenu,
            MF_STRING,
            ID_BRING_TO_FRONT as usize,
            bring_to_front.as_ptr(),
        );
        AppendMenuW(hmenu, MF_STRING, ID_MINIMIZE as usize, minimize.as_ptr());
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(hmenu, MF_STRING, ID_QUIT as usize, quit.as_ptr());

        let mut pt = Point { x: 0, y: 0 };
        GetCursorPos(&mut pt);

        SetForegroundWindow(hwnd);

        let cmd = TrackPopupMenu(
            hmenu,
            TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_NONOTIFY | TPM_RETURNCMD,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );

        DestroyMenu(hmenu);

        if cmd > 0 {
            handle_menu_command(cmd as u16);
        }
    }
}

fn handle_menu_command(cmd: u16) {
    let tx_guard = TRAY_TX.lock().unwrap();
    if let Some(ref tx) = *tx_guard {
        match cmd {
            ID_BRING_TO_FRONT => {
                let _ = tx.send(TrayMessage::BringToFront);
            }
            ID_MINIMIZE => {
                let _ = tx.send(TrayMessage::Minimize);
            }
            ID_QUIT => {
                let _ = tx.send(TrayMessage::Quit);
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: isize,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        WM_TRAYICON => {
            let event = (lparam & 0xFFFF) as u32;
            match event {
                WM_RBUTTONUP => {
                    show_context_menu(hwnd);
                }
                WM_LBUTTONDBLCLK => {
                    let tx_guard = TRAY_TX.lock().unwrap();
                    if let Some(ref tx) = *tx_guard {
                        let _ = tx.send(TrayMessage::BringToFront);
                    }
                }
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            let cmd = (wparam & 0xFFFF) as u16;
            handle_menu_command(cmd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn create_tray_icon(hwnd: isize) -> bool {
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());

        // Try to load custom icon from resources using LoadImageW for better control
        // LR_DEFAULTSIZE (0x40) uses system default icon size
        // IMAGE_ICON = 1, Icon resource ID = 1 (winres default)
        let mut hicon = LoadImageW(
            hinstance,
            1 as *const u16, // MAKEINTRESOURCE(1)
            1,               // IMAGE_ICON
            0,               // cx (0 = use default)
            0,               // cy (0 = use default)
            0x40,            // LR_DEFAULTSIZE
        );

        // Fall back to system default icon if custom icon not found
        if hicon == 0 {
            hicon = LoadIconW(0, IDI_APPLICATION);
        }

        let mut tip: [u16; 128] = [0; 128];
        let tip_text = to_wide("Bunker Proxy");
        for (i, &c) in tip_text.iter().take(127).enumerate() {
            tip[i] = c;
        }

        let nid = NotifyIconDataW {
            cbsize: std::mem::size_of::<NotifyIconDataW>() as u32,
            hwnd,
            uid: 1,
            uflags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            ucallbackmessage: WM_TRAYICON,
            hicon,
            sztip: tip,
            dwstate: 0,
            dwstatemask: 0,
            szinfo: [0; 256],
            u: 0,
            szinfotitle: [0; 64],
            dwinfoflag: 0,
            guiditem: [0; 16],
            hballoonicon: 0,
        };

        Shell_NotifyIconW(NIM_ADD, &nid) != 0
    }
}

fn remove_tray_icon(hwnd: isize) {
    unsafe {
        let nid = NotifyIconDataW {
            cbsize: std::mem::size_of::<NotifyIconDataW>() as u32,
            hwnd,
            uid: 1,
            uflags: 0,
            ucallbackmessage: 0,
            hicon: 0,
            sztip: [0; 128],
            dwstate: 0,
            dwstatemask: 0,
            szinfo: [0; 256],
            u: 0,
            szinfotitle: [0; 64],
            dwinfoflag: 0,
            guiditem: [0; 16],
            hballoonicon: 0,
        };

        Shell_NotifyIconW(NIM_DELETE, &nid);
    }
}

/// Set up the system tray
pub fn setup_tray(tx: mpsc::Sender<TrayMessage>) -> Result<(), Box<dyn std::error::Error>> {
    // Store the sender globally
    {
        let mut tx_guard = TRAY_TX.lock().unwrap();
        *tx_guard = Some(tx);
    }

    // Spawn the tray thread
    let thread = std::thread::spawn(|| {
        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = to_wide("BunkerTrayClass");

            let wc = WndClassExW {
                cbsize: std::mem::size_of::<WndClassExW>() as u32,
                style: 0,
                lpfnwndproc: window_proc,
                cbclsextra: 0,
                cbwndextra: 0,
                hinstance,
                hicon: 0,
                hcursor: 0,
                hbrbackground: 0,
                lpszmenuname: std::ptr::null(),
                lpszclassname: class_name.as_ptr(),
                hiconsm: 0,
            };

            RegisterClassExW(&wc);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                hinstance,
                std::ptr::null(),
            );

            if hwnd == 0 {
                eprintln!("Failed to create tray window");
                return;
            }

            if !create_tray_icon(hwnd) {
                eprintln!("Failed to create tray icon");
                DestroyWindow(hwnd);
                return;
            }

            // Store hwnd in state
            {
                let mut state_guard = TRAY_STATE.lock().unwrap();
                if let Some(ref mut state) = *state_guard {
                    state.hwnd = hwnd;
                }
            }

            // Message loop
            let mut msg = Msg {
                hwnd: 0,
                message: 0,
                wparam: 0,
                lparam: 0,
                time: 0,
                pt: Point { x: 0, y: 0 },
            };

            while GetMessageW(&mut msg, 0, 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            remove_tray_icon(hwnd);
            DestroyWindow(hwnd);
        }
    });

    // Store the thread handle
    let mut state = TRAY_STATE.lock().unwrap();
    *state = Some(TrayState {
        hwnd: 0, // Will be set by the thread
        _thread: thread,
    });

    Ok(())
}

/// Show the console window
pub fn show_window() {
    unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd != 0 {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

/// Hide the console window
pub fn hide_window() {
    unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd != 0 {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_message_quit() {
        let msg = TrayMessage::Quit;
        match msg {
            TrayMessage::Quit => assert!(true),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_tray_message_minimize() {
        let msg = TrayMessage::Minimize;
        match msg {
            TrayMessage::Minimize => assert!(true),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_tray_message_bring_to_front() {
        let msg = TrayMessage::BringToFront;
        match msg {
            TrayMessage::BringToFront => assert!(true),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_tray_message_clone() {
        let msg = TrayMessage::Quit;
        let cloned = msg.clone();
        match cloned {
            TrayMessage::Quit => assert!(true),
            _ => panic!("Clone failed"),
        }
    }

    #[test]
    fn test_to_wide() {
        let wide = to_wide("Test");
        assert_eq!(
            wide,
            vec!['T' as u16, 'e' as u16, 's' as u16, 't' as u16, 0]
        );
    }

    #[test]
    fn test_to_wide_empty() {
        let wide = to_wide("");
        assert_eq!(wide, vec![0]);
    }
}
