
// CrackClientDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "CrackClient.h"
#include "CrackClientDlg.h"
#include "afxdialogex.h"
#include "afxinet.h"
#include <winhttp.h>
#include <afxwin.h>
#include <windows.h>
#pragma comment(lib, "winhttp.lib")
#include <string>
#include <winbase.h>    // For OutputDebugStringA
#include <atlstr.h>     // For CStringA
#include <Atlconv.h>
#include <string>
#include <vector>
#include <afx.h>       // For CTime
#include <atlconv.h>   // For string conversion between CString and std::string
#include <time.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h> 
#include <sstream>   // Ensure this header is included
#include <iomanip> 
#include <iostream>
#include "HomeDialog.h"
#include <wincrypt.h>
#include <fstream>
#include <winternl.h>
#include <wininet.h>


using json = nlohmann::json;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


//CString endTime;
//tm serverEndTime;
// CAboutDlg dialog used for App About

HANDLE hGlobalMutex;

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();


// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()

// CCrackClientDlg dialog
BOOL IsFunctionHooked(void* functionAddress, const BYTE* expectedBytes, size_t length) {
    BYTE* originalBytes = new BYTE[length];
    if (!originalBytes) return FALSE;

    // Protect the memory to allow reading
    DWORD oldProtect;
    if (!VirtualProtect(functionAddress, length, PAGE_EXECUTE_READ, &oldProtect)) {
        delete[] originalBytes;
        return FALSE;
    }

    // Read the original bytes of the function
    SIZE_T bytesRead;
    if (!ReadProcessMemory(GetCurrentProcess(), functionAddress, originalBytes, length, &bytesRead) || bytesRead != length) {
        VirtualProtect(functionAddress, length, oldProtect, &oldProtect);
        delete[] originalBytes;
        return FALSE;
    }

    // Restore the original memory protection
    VirtualProtect(functionAddress, length, oldProtect, &oldProtect);

    // Compare the bytes
    BOOL hooked = memcmp(originalBytes, expectedBytes, length) != 0;

    delete[] originalBytes;
    return hooked;
}

bool IsProxyEnabled() {
    INTERNET_PER_CONN_OPTION_LIST list;
    DWORD dwBufSize = sizeof(list);
    list.dwSize = sizeof(list);

    // Requesting proxy settings for LAN connection
    list.pszConnection = NULL;

    list.dwOptionCount = 1;
    list.dwOptionError = 0;
    INTERNET_PER_CONN_OPTION option;
    list.pOptions = &option;
    option.dwOption = INTERNET_PER_CONN_FLAGS;

    if (!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &dwBufSize)) {
        return false; // Unable to query
    }

    return (list.pOptions->Value.dwValue & PROXY_TYPE_PROXY) != 0;
}

void DetectAndExitOnProxySettings() {
    if (IsProxyEnabled()) {
        MessageBox(NULL, L"Proxy detected! Exiting...", L"Warning", MB_OK);
        ExitProcess(1);
    }
}


void DumpFunctionBytes(void* functionAddress, size_t length) {
    BYTE* functionBytes = new BYTE[length];

    // Read the function's bytes
    SIZE_T bytesRead;
    ReadProcessMemory(GetCurrentProcess(), functionAddress, functionBytes, length, &bytesRead);

    if (bytesRead == length) {
        // Print or log the bytes in hex format
        CString byteStr;
        for (size_t i = 0; i < length; ++i) {
            CString hexByte;
            hexByte.Format(_T("0x%02X "), functionBytes[i]);
            byteStr += hexByte;
        }

        AfxMessageBox(_T("Function bytes: ") + byteStr);
    }

    delete[] functionBytes;
}


// Function to check if a debugger is attached
bool CheckDebugger() {
    BOOL isDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger);
    return isDebugger;
}

// Terminate if debugger is detected
void DetectAndExitOnHook() {
    if (CheckDebugger()) {
        MessageBox(NULL, L"Debugger detected! Exiting...", L"Warning", MB_OK);
        ExitProcess(1);
    }
}


CCrackClientDlg::CCrackClientDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CRACKCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCrackClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CCrackClientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
    ON_WM_CLOSE()
    ON_WM_DESTROY()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_QUIT, &CCrackClientDlg::OnBnClickedQuit)
	ON_BN_CLICKED(IDC_LOGIN, &CCrackClientDlg::OnBnClickedLogin)
	ON_WM_TIMER() // Add this line to handle the timer event
END_MESSAGE_MAP()


// CCrackClientDlg message handlers

void ProtectCodeSection() {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(ProtectCodeSection, &mbi, sizeof(mbi));

    DWORD oldProtect;
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &oldProtect);
}

BOOL CCrackClientDlg::OnInitDialog()
{

	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
    
    // Global Mutex to ensure only one instance of the client runs
    hGlobalMutex = CreateMutex(NULL, TRUE, L"Global\\MyClientMutex");

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        MessageBox(L"Another instance of the client is already running.", L"Error", MB_OK);
        ExitProcess(0); // Exit if another instance is already running
        return FALSE;
    }
    // Other initialization code...
    	// TODO: Add extra initialization here

    DetectAndExitOnHook();
    DetectAndExitOnProxySettings();
    ProtectCodeSection();

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCrackClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CCrackClientDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CCrackClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CCrackClientDlg::OnBnClickedQuit()
{
	// TODO: Add your control notification handler code here
	this->DestroyWindow();
}


void CCrackClientDlg::OnBnClickedLogin()
{
	// TODO: Add your control notification handler code here
	GetDlgItemText(IDC_USERNAME, m_strUsername);
	GetDlgItemText(IDC_PASSWORD, m_strpPassword);
	
	// Send request to server
	SendCredentialsToServer(m_strUsername, m_strpPassword);

}



void DisplayEncodedString(const CString& encodedStr)
{
    // Display the encoded string in a message box
    MessageBox(nullptr, encodedStr, _T("Encoded String"), MB_OK);
}

// Helper function to convert CString to UTF-8 std::string
std::string CStringToUtf8(const CString& cstr)
{
	// Get the length of the UTF-8 string
	int utf8Size = WideCharToMultiByte(CP_UTF8, 0, cstr, -1, NULL, 0, NULL, NULL);
	if (utf8Size <= 0)
		return "";

	// Allocate buffer for UTF-8 string
	std::vector<char> utf8Buffer(utf8Size);

	// Convert to UTF-8
	WideCharToMultiByte(CP_UTF8, 0, cstr, -1, utf8Buffer.data(), utf8Size, NULL, NULL);

	// Return as std::string
	return std::string(utf8Buffer.begin(), utf8Buffer.end() - 1); // Remove trailing null character
}
// Helper function to decrypt AES-256-CBC encrypted data

std::string generateHash(const std::string& username) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(username.c_str()), username.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string DecryptAES256CBC(const std::string& encryptedText, const std::string& keyHex) {
    // Convert hex key to binary
    std::vector<unsigned char> key(32);
    for (size_t i = 0; i < keyHex.size(); i += 2) {
        key[i / 2] = std::stoi(keyHex.substr(i, 2), nullptr, 16);
    }

    // Initialization Vector (IV) is all zeros
    std::vector<unsigned char> iv(16, 0);

    // Convert encrypted text from hex to binary
    std::vector<unsigned char> encryptedData(encryptedText.size() / 2);
    for (size_t i = 0; i < encryptedText.size(); i += 2) {
        encryptedData[i / 2] = std::stoi(encryptedText.substr(i, 2), nullptr, 16);
    }

    // Prepare for decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data(), 0);
    int outlen1, outlen2;
    std::vector<unsigned char> decryptedData(encryptedData.size() + AES_BLOCK_SIZE);

    // Decrypt
    EVP_CipherUpdate(ctx, decryptedData.data(), &outlen1, encryptedData.data(), encryptedData.size());
    EVP_CipherFinal_ex(ctx, decryptedData.data() + outlen1, &outlen2);
    decryptedData.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);

    // Convert decrypted data to string
    return std::string(decryptedData.begin(), decryptedData.end());
}

std::string CStringToStdString(const CString& cstr) {
#ifdef _UNICODE
    // Unicode project
    std::wstring wstr(cstr.GetString());   // Convert CString to std::wstring
    std::string str(CT2A(wstr.c_str()));    // Convert std::wstring to std::string
#else
    // ANSI project
    std::string str(CT2A(cstr));            // Convert CString to std::string
#endif
    return str;
}
void CCrackClientDlg::ParseJsonResponse(const CString& response, const CString& username)
{
    try
    {
        std::string responseStr = CStringToUtf8(response);
        auto jsonResponse = json::parse(responseStr);

        std::string encryptedEndTime = jsonResponse.value("encryptedEndTime", "");
        std::string tokenData = jsonResponse.value("token", "");
        credentialToken = CString(tokenData.c_str());
        //// Decrypt the end time using the user's hash as the key
        std::string hashKey = generateHash(CStringToStdString(username));
        //AfxMessageBox(CString(_T("token: ")) + credentialToken.c_str());

        //AfxMessageBox(CString(_T("hashKey: ")) + hashKey.c_str());
       /* std::string decryptedEndTimeStr = decryptAES(encryptedEndTimeStr, hashKey);

        AfxMessageBox(CString(_T("decryptedEndTimeStr: ")) + decryptedEndTimeStr.c_str());*/

        std::string decryptedEndTime = DecryptAES256CBC(encryptedEndTime, hashKey);

        //AfxMessageBox(CString(_T("decryptedEndTimeStr: ")) + decryptedEndTime.c_str()); 

        // Convert decrypted end time to readable format
        int y, M, d, h, m, s;
        sscanf_s(decryptedEndTime.c_str(), "%d-%d-%dT%d:%d:%d", &y, &M, &d, &h, &m, &s);
        tm time = { 0 };
        time.tm_year = y - 1900;
        time.tm_mon = M - 1;
        time.tm_mday = d;
        time.tm_hour = h;
        time.tm_min = m;
        time.tm_sec = s;

        char formattedTime[100];
        strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", &time);

        CString displayMessage;
        displayMessage.Format(_T("Login successful! End time: %S"), formattedTime);
        AfxMessageBox(displayMessage);
        serverEndTime = time; // Store the parsed end time
        CEdit* pEdit = (CEdit*)GetDlgItem(IDC_USERNAME);
        if (pEdit != nullptr)
        {
            pEdit->DestroyWindow();  // This will delete the control from the dialog.
        }
        GetDlgItem(IDC_PASSWORD)->ShowWindow(SW_HIDE);
        GetDlgItem(IDC_LOGIN)->ShowWindow(SW_HIDE);
        GetDlgItem(ID_QUIT)->ShowWindow(SW_HIDE);
        GetDlgItem(IDC_USERLABEL)->SetWindowText(_T("Succesfully Logged in!"));
        GetDlgItem(IDC_PASSWORDLABEL)->ShowWindow(SW_HIDE);

    }
    catch (json::exception& e)
    {
        CString errorMsg;
        errorMsg.Format(_T("Error parsing JSON response: %s"), e.what());
        AfxMessageBox(errorMsg);
    }
}


void CCrackClientDlg::ParseJsonForEndTime(const CString& response, const CString& username)
{
    try
    {
        std::string responseStr = CStringToUtf8(response);
        auto jsonResponse = json::parse(responseStr);

        std::string encryptedEndTime = jsonResponse.value("hashedEndTime", "");
        //std::string tokenData = jsonResponse.value("token", "");
        //// Decrypt the end time using the user's hash as the key
        std::string hashKey = generateHash(CStringToStdString(username));


        std::string decryptedEndTime = DecryptAES256CBC(encryptedEndTime, hashKey);

        return;
        // Convert decrypted end time to readable format
        int y, M, d, h, m, s;
        sscanf_s(decryptedEndTime.c_str(), "%d-%d-%dT%d:%d:%d", &y, &M, &d, &h, &m, &s);
        tm time = { 0 };
        time.tm_year = y - 1900;
        time.tm_mon = M - 1;
        time.tm_mday = d;
        time.tm_hour = h;
        time.tm_min = m;
        time.tm_sec = s;

        char formattedTime[100];
        strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", &time);

        CString displayMessage;
        displayMessage.Format(_T("Login successful! End time: %S"), formattedTime);
        AfxMessageBox(displayMessage);

        serverEndTime = time; // Store the parsed end time


    }
    catch (json::exception& e)
    {
        CString errorMsg;
        errorMsg.Format(_T("Error parsing JSON response: %s"), e.what());
        AfxMessageBox(errorMsg);
    }
}



void CCrackClientDlg::getEndTimeToServer(const CString& username, const CString& token)
{
    try
    {
        CInternetSession session;
        CHttpConnection* pConnection = nullptr;
        CHttpFile* pFile = nullptr;

        CString serverName = _T("localhost");
        INTERNET_PORT port = 8000;
        CString object = _T("/api/auth/endtime");

        // Format the full request URL
        CString requestUrl;
        requestUrl.Format(_T("http://%s:%d%s"), serverName, port, object);

        // Open HTTP connection to the server
        pConnection = session.GetHttpConnection(serverName, port);

        // Open a request for POST method
        pFile = pConnection->OpenRequest(CHttpConnection::HTTP_VERB_POST, object);

        // Format the POST data with username and token
        CString postData;
        postData.Format(_T("{\"username\": \"%s\", \"token\": \"%s\"}"), username, token);
        std::string utf8PostData = CStringToUtf8(postData);

        // Add required headers for content type
        CString headers;
        headers.Format(_T("Content-Type: application/json; charset=UTF-8\r\n"));

        // Send the request to the server
        pFile->SendRequest(headers, headers.GetLength(), (LPVOID)utf8PostData.c_str(), utf8PostData.length());

        // Query the response status code
        DWORD dwRet;
        pFile->QueryInfoStatusCode(dwRet);

        CString response;
        BYTE buffer[1024];
        int bytesRead;
        while ((bytesRead = pFile->Read(buffer, sizeof(buffer))) > 0)
        {
            response.Append(CString(reinterpret_cast<LPCSTR>(buffer), bytesRead));
        }

        CString displayMessage;
        if (dwRet == HTTP_STATUS_OK)
        {
            // Parse the JSON response to extract the end time
            ParseJsonForEndTime(response, username);
        }
        else
        {
            displayMessage.Format(_T("Request failed. Status code: %d\nResponse: %s"), dwRet, response);
            AfxMessageBox(displayMessage);
            this->DestroyWindow();
        }

        // Clean up
        if (pFile) pFile->Close();
        if (pConnection) pConnection->Close();
        session.Close();

        // Set a timer to periodically check the end time
    }
    catch (CInternetException* pEx)
    {
        TCHAR szError[1024];
        pEx->GetErrorMessage(szError, 1024);
        AfxMessageBox(CString(_T("Internet exception: ")) + szError);
        pEx->Delete();
        this->DestroyWindow();
    }
}


void CCrackClientDlg::SendCredentialsToServer(const CString& username, const CString& password)
{
    // Protect the function from being modified in memory
    ProtectCodeSection();

    try
    {
        CInternetSession session;
        CHttpConnection* pConnection = nullptr;
        CHttpFile* pFile = nullptr;

        CString serverName = _T("localhost");
        INTERNET_PORT port = 8000;
        CString object = _T("/api/auth/login");

        CString requestUrl;
        requestUrl.Format(_T("http://%s:%d%s"), serverName, port, object);

        pConnection = session.GetHttpConnection(serverName, port);
        pFile = pConnection->OpenRequest(CHttpConnection::HTTP_VERB_POST, object);

        CString postData;
        postData.Format(_T("{\"username\": \"%s\", \"password\": \"%s\"}"), username, password);
        std::string utf8PostData = CStringToUtf8(postData);

        CString headers;
        headers.Format(_T("Content-Type: application/json; charset=UTF-8\r\n"));

        //// Check if SendRequest is hooked
        //if (IsFunctionHooked((void*)pFile->SendRequest)) {
        //    AfxMessageBox(_T("SendRequest function is hooked!"));
        //    return;
        //}

        pFile->SendRequest(headers, headers.GetLength(), (LPVOID)utf8PostData.c_str(), utf8PostData.length());

        DWORD dwRet;
        pFile->QueryInfoStatusCode(dwRet);

        CString response;
        BYTE buffer[1024];
        int bytesRead;
        while ((bytesRead = pFile->Read(buffer, sizeof(buffer))) > 0)
        {
            response.Append(CString(reinterpret_cast<LPCSTR>(buffer), bytesRead));
        }

        CString displayMessage;
        if (dwRet == HTTP_STATUS_OK)
        {
            // Parse the JSON response to extract the hash and encrypted end time
            ParseJsonResponse(response, username);
        }
        else
        {
            displayMessage.Format(_T("Request failed. Status code: %d\nResponse: %s"), dwRet, response);
            AfxMessageBox(displayMessage);
        }

        if (pFile) pFile->Close();
        if (pConnection) pConnection->Close();
        session.Close();

        // Set a timer for periodic checks or updates
        SetTimer(1, 6000, NULL);
    }
    catch (CInternetException* pEx)
    {
        TCHAR szError[1024];
        pEx->GetErrorMessage(szError, 1024);
        AfxMessageBox(CString(_T("Internet exception: ")) + szError);
        pEx->Delete();
        this->DestroyWindow();
    }
}


void CCrackClientDlg::OnTimer(UINT_PTR nIDEvent)
{

    

    if (nIDEvent == 1) // Timer with ID 1
    {
        // Request updated end time from server

        COleDateTime currentTime = COleDateTime::GetCurrentTime();
        
        // Convert tm to COleDateTime
        COleDateTime endDateTime(
            serverEndTime.tm_year + 1900, // Year since 1900
            serverEndTime.tm_mon + 1,     // Month is 0-based
            serverEndTime.tm_mday,        // Day of the month
            serverEndTime.tm_hour,        // Hours
            serverEndTime.tm_min,         // Minutes
            serverEndTime.tm_sec          // Seconds
        );
        CString currentTimeStr = currentTime.Format(_T("%Y-%m-%d %H:%M:%S"));
        CString endTimeStr = endDateTime.Format(_T("%Y-%m-%d %H:%M:%S"));

        // Check if the current time is greater than the server end time
        if (currentTime > endDateTime)
        {
            AfxMessageBox(_T("Session expired. The application will now close."));
            this->DestroyWindow();
            // Exit the application
        }
        else {

            //SendCredentialsToServer(_T("v"), _T("v")); // Example: use saved credentials or adjust as needed
            //SendCredentialsToServer(m_strUsername, m_strpPassword);
            getEndTimeToServer(m_strUsername, credentialToken);
        }
    }

    // Call the base class OnTimer to ensure the default handling occurs
    CDialogEx::OnTimer(nIDEvent);
}

void CCrackClientDlg::NotifyServerOnQuit(const CString& username, const CString& token)
{
    try
    {
        CInternetSession session;
        CHttpConnection* pConnection = nullptr;
        CHttpFile* pFile = nullptr;

        CString serverName = _T("localhost");
        INTERNET_PORT port = 8000;
        CString object = _T("/api/client/quit");

        // Format the full request URL
        CString requestUrl;
        requestUrl.Format(_T("http://%s:%d%s"), serverName, port, object);

        // Open HTTP connection to the server
        pConnection = session.GetHttpConnection(serverName, port);

        // Open a request for POST method 
        pFile = pConnection->OpenRequest(CHttpConnection::HTTP_VERB_POST, object);

        // You can send the username or other identifier in the request
        CString postData;
        postData.Format(_T("{\"username\": \"%s\", \"token\": \"%s\"}"), username, token);
        std::string utf8PostData = CStringToUtf8(postData);

        // Add required headers for content type
        CString headers;
        headers.Format(_T("Content-Type: application/json; charset=UTF-8\r\n"));

        // Send the request to the server
        pFile->SendRequest(headers, headers.GetLength(), (LPVOID)utf8PostData.c_str(), utf8PostData.length());

        // Clean up
        if (pFile) pFile->Close();
        if (pConnection) pConnection->Close();
        session.Close();
    }
    catch (CInternetException* pEx)
    {
        TCHAR szError[1024];
        pEx->GetErrorMessage(szError, 1024);
        //AfxMessageBox(CString(_T("Internet exception: ")) + szError);
        pEx->Delete();
    }
}


// Alternatively, override the OnDestroy method to handle the same logic
void CCrackClientDlg::OnDestroy()
{
    // Notify the server before quitting
    NotifyServerOnQuit(m_strUsername, credentialToken);

    // Call the base class implementation
    CDialogEx::OnDestroy();
}
