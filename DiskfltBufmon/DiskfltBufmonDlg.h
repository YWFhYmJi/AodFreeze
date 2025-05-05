
// DiskfltBufmonDlg.h : header file
//

#pragma once

#define UM_TRAYNOTIFY WM_USER + 11

// CDiskfltBufmonDlg dialog
class CDiskfltBufmonDlg : public CDialog
{
// Construction
public:
	CDiskfltBufmonDlg(CWnd* pParent = nullptr);	// standard constructor
	~CDiskfltBufmonDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DISKFLTBUFMON_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	NOTIFYICONDATA m_nid;
	afx_msg LRESULT OnTrayNotify(WPARAM wParam, LPARAM lParam);
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedRefresh();
	CListCtrl m_volumeList;
	HANDLE m_hMutex;
	DWORD m_diskNum[26], m_partNum[26];
	CHAR GetVolLetterFromStorNum(DWORD diskNum, DWORD partNum);
};
