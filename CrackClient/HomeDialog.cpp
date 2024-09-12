// HomeDialog.cpp : implementation file
//

#include "pch.h"
#include "CrackClient.h"
#include "afxdialogex.h"
#include "HomeDialog.h"


// HomeDialog dialog

IMPLEMENT_DYNAMIC(HomeDialog, CDialogEx)

HomeDialog::HomeDialog(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

HomeDialog::~HomeDialog()
{
}

void HomeDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(HomeDialog, CDialogEx)
END_MESSAGE_MAP()


// HomeDialog message handlers
