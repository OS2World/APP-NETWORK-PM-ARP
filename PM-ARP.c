//=============================================================================
// PM-ARP.c
// Программа для работы со стеком ARP
//=============================================================================
#define INCL_WIN
#define INCL_DOSPROCESS
#define INCL_DOSSEMAPHORES

#include <os2.h>
#include <libc\stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <types.h>
#include <sys\socket.h>
#include <sys\ioctl.h>
#include <netinet\in.h>
#include <net\route.h>
#include <net\if.h>
#include <net\if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "PM-ARP.h"

//-----------------------------------------------------------------------------
// Dialog Window procedure prototype
//-----------------------------------------------------------------------------
MRESULT EXPENTRY DlgMenu(HWND, ULONG ,MPARAM, MPARAM);
MRESULT EXPENTRY DlgProcAdd (HWND, ULONG, MPARAM, MPARAM); // Dlg proc
MRESULT EXPENTRY DlgProcChg (HWND, ULONG, MPARAM, MPARAM); // Dlg proc
void InitContainer(HWND);
void InsertRecord(HWND, int);
void DeleteRecord(HWND);
void DeleteAll(HWND);
void DoRefresh(HWND);
void APIENTRY DoScan(ULONG);

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
#pragma pack(1)
struct  oarptab { // Модифицированныое описание
        struct  in_addr at_iaddr;       /* internet address */
        struct  in_addr dummy_iaddr;    // не знаю об этом - заполним 4 байта
        u_char  at_enaddr[6];           /* ethernet address */
        u_char  at_timer;               /* minutes since last reference */
        u_char  at_flags;               /* flags */
        void * at_hold;                 // с ядром мы все равно не работаем
        u_short at_rcf;                 /* token ring routing control field */
        u_short at_rseg[8];             /* token ring routing segments */
        u_long  at_millisec;            /* TOD milliseconds of last update */
        u_short at_interface;           /* interface index */
};
#pragma pack()

typedef struct _USERRECORD_ARP
  { RECORDCORE  recordCore;
    PSZ         IP;
    PSZ         MAC;
    PSZ         COMPLETED;
    PSZ         PERMANENT;
    PSZ         PUBLIC;
    PSZ         LAST_USED;
  } USERRECORD_ARP, *PUSERRECORD_ARP;
HPOINTER hIcon;
TID tid = 0;
HEV hevEventHandle;
char *ARPtptr;
char *IPptr, *MACptr, *COMPLptr, *PERMptr, *PUBLptr, *LTIMEptr, *NUMptr;
char strNULL[] = "";
int NumARP = L0, Sel = L0;

//=============================================================================
// Main procedure
//=============================================================================
void main(void)
  {
  HAB hab = WinInitialize(L0);          // Anchor
  HMQ hmq = WinCreateMsgQueue(hab, L0); // Message queue handle

  WinDlgBox( HWND_DESKTOP,
             HWND_DESKTOP,
             DlgMenu,
             NULLHANDLE,
             DIALOGWIN,
             L0 );

  WinDestroyMsgQueue(hmq);
  WinTerminate(hab);
  }

//=============================================================================
// Dialog procedure
//=============================================================================
MRESULT EXPENTRY DlgMenu (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
  {
  switch (msg)
    {
//-----------------------------------------------------------------------------
// Handle the initialization of the dialog -
// i. e. Set Priority for current Thread,
//       Set icon, Attach Menu, Initiate Container,
//       Create Semaphor and 2-nd Thread
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L16, L0);

      hIcon = (HPOINTER)WinLoadPointer(HWND_DESKTOP, NULLHANDLE, L1);
      WinSendMsg(hwndDlg, WM_SETICON, (MPARAM)hIcon, L0);

      WinLoadMenu(hwndDlg, NULLHANDLE, MAINMENU);
      WinSendMsg(hwndDlg, WM_UPDATEFRAME, (MPARAM)FCF_MENU, L0);

      InitContainer(hwndDlg);

      DosCreateEventSem( (ULONG)NULL, &hevEventHandle, DC_SEM_SHARED, L1 );
      DosCreateThread( &tid, (PFNTHREAD)DoScan, hwndDlg,
                       CREATE_READY | STACK_SPARSE, L65536 );
      break;
      }
//-----------------------------------------------------------------------------
// Выведем с контекстное меню
//-----------------------------------------------------------------------------
    case WM_CONTROL:
      {
      switch (SHORT2FROMMP(mp1))
        {
        case CN_CONTEXTMENU:
          {
          POINTL pt;
          HWND hwndPopup = WinLoadMenu(hwndDlg, NULLHANDLE, POPUPMENU);
          WinQueryPointerPos(HWND_DESKTOP, &pt);
          WinPopupMenu(HWND_DESKTOP, hwndDlg, hwndPopup, pt.x, pt.y, L0,
                       PU_HCONSTRAIN | PU_VCONSTRAIN |
                       PU_MOUSEBUTTON1 | PU_KEYBOARD);
          return (MRFROMLONG(TRUE));
          }
//-----------------------------------------------------------------------------
// Запомним номер текущей ззаписи
//-----------------------------------------------------------------------------
        case CN_EMPHASIS:
          {
          PNOTIFYRECORDEMPHASIS Selected = (PNOTIFYRECORDEMPHASIS)mp2;

          if ( CRA_SELECTED & Selected->fEmphasisMask )
            Sel=atoi(Selected->pRecord->pszIcon);
          break;
          }
//-----------------------------------------------------------------------------
// Обработаем двойной щелчок по строке
//-----------------------------------------------------------------------------
        case CN_ENTER:
          {
          DeleteRecord(hwndDlg);
          break;
          }
        }
      break;
      }
//-----------------------------------------------------------------------------
// Обработка меню
//-----------------------------------------------------------------------------
    case WM_INITMENU:
      {
      switch (SHORT1FROMMP(mp1))
        {
        case IDM_EDIT:
          {
          ULONG Post;

          DosQueryEventSem( hevEventHandle, &Post );
          WinEnableMenuItem((HWND)mp2, IDM_ADD,    Post == L0);
          WinEnableMenuItem((HWND)mp2, IDM_DELETE, Post == L0);
          WinEnableMenuItem((HWND)mp2, IDM_CHANGE, Post == L0);
          WinEnableMenuItem((HWND)mp2, IDM_PURGE,  Post == L0);
          break;
          }

        case FID_MENU:
          {
          ULONG Post;

          DosQueryEventSem( hevEventHandle, &Post );
          WinEnableMenuItem((HWND)mp2, POP_ADD,    Post == L0);
          WinEnableMenuItem((HWND)mp2, POP_DELETE, Post == L0);
          WinEnableMenuItem((HWND)mp2, POP_CHANGE, Post == L0);
          WinEnableMenuItem((HWND)mp2, POP_PURGE,  Post == L0);
          break;
          }
        }
      break;
      }
//-----------------------------------------------------------------------------
// Сканирование кэша ARP завершено
//-----------------------------------------------------------------------------
    case WM_USER_SCAN_DONE:
      {
      WinEnableControl(hwndDlg, PB_PURGE,   TRUE);
      WinEnableControl(hwndDlg, PB_ADD,     TRUE);
      WinEnableControl(hwndDlg, PB_DELETE,  TRUE);
      WinEnableControl(hwndDlg, PB_CHANGE,  TRUE);
      WinEnableControl(hwndDlg, PB_REFRESH, TRUE);
      break;
      }
//-----------------------------------------------------------------------------
// Добавим запись в таблицу
//-----------------------------------------------------------------------------
    case WM_USER_LINE_DONE:
      {
      InsertRecord( hwndDlg, LONGFROMMP(mp1) );
      break;
      }
//-----------------------------------------------------------------------------
// Обновим таблицу
//-----------------------------------------------------------------------------
    case WM_USER_REFRESH:
      {
      DoRefresh(hwndDlg);
      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
//-----------------------------------------------------------------------------
// Close the dialog
//-----------------------------------------------------------------------------
        case PB_EXIT:
          {
          WinSendMsg(hwndDlg, WM_CLOSE, L0, L0);
          break;
          }
//-----------------------------------------------------------------------------
// Обработаем кнопку Refresh
//-----------------------------------------------------------------------------
        case PB_REFRESH:
          {
          DoRefresh(hwndDlg);
          return(L0);
          }
//-----------------------------------------------------------------------------
// Обработаем кнопку Delete
//-----------------------------------------------------------------------------
        case PB_DELETE:
        case IDM_DELETE:
        case POP_DELETE:
          {
          DeleteRecord(hwndDlg);
          return(L0);
          }
//-----------------------------------------------------------------------------
// Обработаем кнопку Add
//-----------------------------------------------------------------------------
        case PB_ADD:
        case IDM_ADD:
        case POP_ADD:
          {
          WinDlgBox (HWND_DESKTOP, // Parent
                     hwndDlg,      // Owner
                     DlgProcAdd,   // Dialog window procedure
                     NULLHANDLE,   // Where is dialog resource?
                     ADDWIN,       // Dialog Resource ID
                     L0);          // Create parms (for WM_INITDLG)
          WinPostMsg (hwndDlg, WM_USER_REFRESH, L0, L0);
          return(L0);
          }
//-----------------------------------------------------------------------------
// Обработаем кнопку Change
//-----------------------------------------------------------------------------
        case PB_CHANGE:
        case IDM_CHANGE:
        case POP_CHANGE:
          {
          if ( Sel  >= NumARP ) return(L0);
          WinDlgBox (HWND_DESKTOP, // Parent
                     hwndDlg,      // Owner
                     DlgProcChg,   // Dialog window procedure
                     NULLHANDLE,   // Where is dialog resource?
                     ADDWIN,       // Dialog Resource ID
                     L0);          // Create parms (for WM_INITDLG)
          WinPostMsg (hwndDlg, WM_USER_REFRESH, L0, L0);
          return(L0);
          }
//-----------------------------------------------------------------------------
// Обработаем кнопку Purge
//-----------------------------------------------------------------------------
        case PB_PURGE:
        case IDM_PURGE:
        case POP_PURGE:
          {
          DeleteAll(hwndDlg);
          return(L0);
          }
//-----------------------------------------------------------------------------
// Расскажем о себе
//-----------------------------------------------------------------------------
        case IDM_ABOUT:
          {
          WinDlgBox( HWND_DESKTOP, hwndDlg, WinDefDlgProc,
                     NULLHANDLE, ABOUTWIN, L0 );
          return (L0);
          }
//-----------------------------------------------------------------------------
        }
      }
    }
  return WinDefDlgProc(hwndDlg, msg, mp1, mp2);
  }

//=============================================================================
// DoRefresh - подпрограмма запуска обновления таблицы
//=============================================================================
void DoRefresh(HWND hwnd)
  {
  WinEnableControl(hwnd, PB_PURGE,   FALSE);
  WinEnableControl(hwnd, PB_ADD,     FALSE);
  WinEnableControl(hwnd, PB_DELETE,  FALSE);
  WinEnableControl(hwnd, PB_CHANGE,  FALSE);
  WinEnableControl(hwnd, PB_REFRESH, FALSE);
  DosPostEventSem(hevEventHandle);
  }

//=============================================================================
// DeleteRecord - подпрограмма удаления записи из кэша ARP
//=============================================================================
void DeleteRecord(HWND hwnd)
  {
  struct myarpreq
    {
    struct  sockaddr_in arp_pa;   // protocol address
    struct  sockaddr arp_ha;      // hardware address
    long_int arp_flags;           // flags
    } myarp = { L0 };
  struct oarptab *pARP;
  int sock;
  char Msg[L64];

  if ( Sel  >= NumARP ) return;
  sprintf(Msg, "Do you want to delete ARP entry %s?", IPptr+L16*Sel);
  if ( WinMessageBox( HWND_DESKTOP, hwnd, Msg, Title, L0,
                      MB_OKCANCEL | MB_APPLMODAL |
                      MB_ICONQUESTION ) != MBID_OK ) return;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  pARP = (struct oarptab *)ARPtptr+Sel;
  myarp.arp_pa.sin_family = AF_INET;
  myarp.arp_pa.sin_addr.s_addr = pARP->at_iaddr.s_addr;
  memcpy( &myarp.arp_ha.sa_data, pARP->at_enaddr, sizeof(pARP->at_enaddr) );
  myarp.arp_flags = pARP->at_flags;
  ioctl(sock, SIOCDARP, (char *)&myarp, sizeof(myarp));
  soclose(sock);

  WinPostMsg (hwnd, WM_USER_REFRESH, L0, L0);
  }

//=============================================================================
// DeleteAll - подпрограмма удаления всех записей из кэша ARP
//=============================================================================
void DeleteAll(HWND hwnd)
  {
  struct myarpreq
    {
    struct  sockaddr_in arp_pa;   // protocol address
    struct  sockaddr arp_ha;      // hardware address
    long_int arp_flags;           // flags
    } myarp;
  struct oarptab *pARP;
  int sock, i;

  if ( Sel  >= NumARP ) return;
  if ( WinMessageBox( HWND_DESKTOP, hwnd,
                      "Do you want to clear ARP cache?", Title, L0,
                      MB_OKCANCEL | MB_APPLMODAL |
                      MB_ICONQUESTION ) != MBID_OK ) return;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  for ( pARP = (struct oarptab *)ARPtptr, i=L0; i<NumARP; i++, pARP++ )
    {
    memset(&myarp, L0, sizeof(myarp));
    myarp.arp_pa.sin_family = AF_INET;
    myarp.arp_pa.sin_addr.s_addr = pARP->at_iaddr.s_addr;
    memcpy( &myarp.arp_ha.sa_data, pARP->at_enaddr, sizeof(pARP->at_enaddr) );
    myarp.arp_flags = pARP->at_flags;
    ioctl(sock, SIOCDARP, (char *)&myarp, sizeof(myarp));
    }

  soclose(sock);
  WinPostMsg (hwnd, WM_USER_REFRESH, L0, L0);
  }

//=============================================================================
// DoScan - подпрограмма просмотра кэша ARP
//=============================================================================
void APIENTRY DoScan(ULONG parmHwnd)
  {
  ULONG ulPostCnt = L0, *pLen;
  int sock, i;
  struct oarptab *pARP;

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);

  IPptr    = malloc(L16*NUMARP);
  MACptr   = malloc(L15*NUMARP);
  COMPLptr = malloc(L2*NUMARP);
  PERMptr  = malloc(L2*NUMARP);
  PUBLptr  = malloc(L2*NUMARP);
  LTIMEptr = malloc(L11*NUMARP);
  NUMptr   = malloc(L6*NUMARP);
  ARPtptr  = malloc(sizeof(struct oarptab)*NUMARP);

  for (;;)
    {
    DosWaitEventSem(hevEventHandle, SEM_INDEFINITE_WAIT);

    WinPostMsg( WinWindowFromID(parmHwnd, ID_CONTAINER), // Очистим контейнер
                CM_REMOVERECORD, NULL,
                MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );

    NumARP = L0;
    memset(IPptr,    L0, L16*NUMARP);
    memset(MACptr,   L0, L15*NUMARP);
    memset(COMPLptr, L0, L2*NUMARP);
    memset(PERMptr,  L0, L2*NUMARP);
    memset(PUBLptr,  L0, L2*NUMARP);
    memset(LTIMEptr, L0, L11*NUMARP);
    memset(NUMptr,   L0, L6*NUMARP);
    memset(ARPtptr,  L0, sizeof(struct oarptab)*NUMARP);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    os2_ioctl(sock, SIOSTATARP, ARPtptr, sizeof(struct oarptab)*NUMARP);
    soclose(sock);

    pLen = (ULONG *)ARPtptr;
    if ( *pLen != (sizeof(struct oarptab)*NUMARP) )
      {
      for ( i=L0, pARP=(struct oarptab *)ARPtptr; i<NUMARP; i++, pARP++ )
        {
        pLen = (ULONG *)pARP;
        if ( *pLen == L0 ) break;

        sprintf(NUMptr+L6*i, "%d", i);
        sprintf(IPptr+L16*i, "%s", inet_ntoa(pARP->at_iaddr));
        sprintf( MACptr+L15*i, "%2.2x%2.2x-%2.2x%2.2x-%2.2x%2.2x",
                pARP->at_enaddr[L0],pARP->at_enaddr[L1],pARP->at_enaddr[L2],
                pARP->at_enaddr[L3],pARP->at_enaddr[L4],pARP->at_enaddr[L5] );

        sprintf(LTIMEptr+L11*i, "%d", pARP->at_timer);
        if ( pARP->at_flags & ATF_COM  ) COMPLptr[L2*i] = 'Y';
        if ( pARP->at_flags & ATF_PERM ) PERMptr[L2*i]  = 'Y';
        if ( pARP->at_flags & ATF_PUBL ) PUBLptr[L2*i]  = 'Y';
        NumARP++;
        WinPostMsg (parmHwnd, WM_USER_LINE_DONE, MPFROMLONG(i), L0);
        }
      }

    DosResetEventSem( hevEventHandle, &ulPostCnt );
    WinPostMsg (parmHwnd, WM_USER_SCAN_DONE, L0, L0);
    }
  }

//=============================================================================
// InitContainer - подпрограмма инициализации контейнера
//=============================================================================
void InitContainer(HWND hwnd)
  {
  static char pszCnrTitle[] = "ARP cache";
  static CNRINFO cnrinfo;
  static PFIELDINFO pFieldInfo, firstFieldInfo;
  static FIELDINFOINSERT fieldInfoInsert;
  static PFIELDINFOINSERT pFieldInfoInsert;
  static char pszColumnText1[]= "IP address";
  static char pszColumnText2[]= "MAC address";
  static char pszColumnText3[]= "Completed";
  static char pszColumnText4[]= "Permanent";
  static char pszColumnText5[]= "Public";
  static char pszColumnText6[]= "Last used";
  static u_long MsgFlg = CMA_FLWINDOWATTR | CMA_CNRTITLE;
  static long NumCol = L6;

  cnrinfo.pszCnrTitle = pszCnrTitle;
  cnrinfo.flWindowAttr = CV_DETAIL | CA_CONTAINERTITLE |
                         CA_TITLESEPARATOR | CA_DETAILSVIEWTITLES;

  pFieldInfo=WinSendDlgItemMsg(hwnd, ID_CONTAINER, CM_ALLOCDETAILFIELDINFO,
                               MPFROMLONG(NumCol), NULL);
  firstFieldInfo = pFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText1;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, IP);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText2;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, MAC);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_CENTER;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText3;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, COMPLETED);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_CENTER;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText4;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, PERMANENT);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_CENTER|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText5;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, PUBLIC);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING | CFA_HORZSEPARATOR | CFA_RIGHT;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText6;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_ARP, LAST_USED);

  cnrinfo.cFields = NumCol;
  fieldInfoInsert.cFieldInfoInsert = NumCol;

  fieldInfoInsert.cb = (ULONG)(sizeof(FIELDINFOINSERT));
  fieldInfoInsert.pFieldInfoOrder = (PFIELDINFO)CMA_FIRST;
  fieldInfoInsert.fInvalidateFieldInfo = TRUE;

  pFieldInfoInsert = &fieldInfoInsert;

  WinSendDlgItemMsg( hwnd,
                     ID_CONTAINER,
                     CM_INSERTDETAILFIELDINFO,
                     MPFROMP(firstFieldInfo),
                     MPFROMP(pFieldInfoInsert) );

  WinSendDlgItemMsg( hwnd,
                     ID_CONTAINER,
                     CM_SETCNRINFO,
                     &cnrinfo,
                     MPFROMLONG(MsgFlg) );
  }

//=============================================================================
// InsertRecord - подпрограмма добавления записи в контейнер
//=============================================================================
void InsertRecord(HWND hwnd, int i)
  {
  ULONG  cbRecordData;
  static PUSERRECORD_ARP pUserRecord;
  static RECORDINSERT recordInsert;

  cbRecordData = (LONG) (sizeof(USERRECORD_ARP) - sizeof(RECORDCORE));
  pUserRecord = WinSendDlgItemMsg( hwnd,
                                   ID_CONTAINER,
                                   CM_ALLOCRECORD,
                                   MPFROMLONG(cbRecordData),
                                   MPFROMSHORT(L1) );

  pUserRecord->recordCore.cb       = sizeof(RECORDCORE);
  pUserRecord->recordCore.pszText  = strNULL;
  pUserRecord->recordCore.pszIcon  = (PSZ)NUMptr+L6*i;
  pUserRecord->recordCore.pszName  = strNULL;
  pUserRecord->recordCore.hptrIcon = hIcon;

  pUserRecord->IP        = (PSZ)IPptr+L16*i;
  pUserRecord->MAC       = (PSZ)MACptr+L15*i;
  pUserRecord->COMPLETED = (PSZ)COMPLptr+L2*i;
  pUserRecord->PERMANENT = (PSZ)PERMptr+L2*i;
  pUserRecord->PUBLIC    = (PSZ)PUBLptr+L2*i;
  pUserRecord->LAST_USED = (PSZ)LTIMEptr+L11*i;

  recordInsert.cb                = sizeof(RECORDINSERT);
  recordInsert.pRecordParent     = NULL;
  recordInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
  recordInsert.zOrder            = CMA_TOP;
  recordInsert.cRecordsInsert    = L1;
  recordInsert.fInvalidateRecord = TRUE;

  WinPostMsg( WinWindowFromID(hwnd, ID_CONTAINER),
              CM_INSERTRECORD,
              (PRECORDCORE)pUserRecord,
              &recordInsert );
  }

//=============================================================================
// DlgProcAdd - подпрограмма добавления записи в кэш ARP
//=============================================================================
MRESULT EXPENTRY DlgProcAdd(HWND hwnd, ULONG msg, MPARAM mp1, MPARAM mp2)
  {
  struct myarpreq
    {
    struct  sockaddr_in arp_pa;   // protocol address
    struct  sockaddr arp_ha;      // hardware address
    long_int arp_flags;           // flags
    } myarp;
  int i, sock;
  char IPaddr[L16], MAC1[L5], MAC2[L5], MAC3[L5], MAC[L13];

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSetWindowText(hwnd, "Add ARP entry");

      WinSendDlgItemMsg(hwnd, EF_IP, EM_SETTEXTLIMIT, (MPARAM)L15, L0);

      WinSendDlgItemMsg(hwnd, EF_MAC1, EM_SETTEXTLIMIT, (MPARAM)L4, L0);
      WinSendDlgItemMsg(hwnd, EF_MAC2, EM_SETTEXTLIMIT, (MPARAM)L4, L0);
      WinSendDlgItemMsg(hwnd, EF_MAC3, EM_SETTEXTLIMIT, (MPARAM)L4, L0);

      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
        case DID_OK:
          {
          if ( WinQueryDlgItemTextLength(hwnd, EF_IP) < L7 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_IP));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC1) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC1));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC2) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC2));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC3) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC3));
            return(L0);
            }

          memset(&myarp, L0, sizeof(myarp));

          WinQueryDlgItemText(hwnd, EF_IP, L16, IPaddr);
          if ((myarp.arp_pa.sin_addr.s_addr=inet_addr(IPaddr)) == INADDR_NONE)
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_IP));
            return(L0);
            }

          WinQueryDlgItemText(hwnd, EF_MAC1, L5, MAC1);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC1[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC1));
              return(L0);
              }
            }
          WinQueryDlgItemText(hwnd, EF_MAC2, L5, MAC2);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC2[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC2));
              return(L0);
              }
            }
          WinQueryDlgItemText(hwnd, EF_MAC3, L5, MAC3);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC3[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC3));
              return(L0);
              }
            }

          strcpy(MAC, MAC1);
          strcat(MAC, MAC2);
          strcat(MAC, MAC3);

          for ( i=L0; i<L6; i++)
            {
            if ( isdigit(MAC[L2*i]) )
              myarp.arp_ha.sa_data[i] = (MAC[L2*i]-'0') << L4;
            else myarp.arp_ha.sa_data[i] = (toupper(MAC[L2*i])-'A'+'\x0a')<<L4;
            if ( isdigit(MAC[L2*i+L1]) )
              myarp.arp_ha.sa_data[i] |= MAC[L2*i+L1]-'0';
            else myarp.arp_ha.sa_data[i] |= toupper(MAC[L2*i+L1])-'A'+'\x0a';
            }
          myarp.arp_pa.sin_family = AF_INET;
          if ( WinQueryButtonCheckstate(hwnd, CB_PERM) )
            myarp.arp_flags |= ATF_PERM;
          if ( WinQueryButtonCheckstate(hwnd, CB_PUBL) )
            myarp.arp_flags |= ATF_PUBL;

          sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
          ioctl(sock, SIOCSARP, (char *)&myarp, sizeof(myarp));
          soclose(sock);

          break;
          }
        }
      }
      break;
    }
  return (WinDefDlgProc (hwnd,msg,mp1,mp2));
  }

//=============================================================================
// DlgProcChg - подпрограмма изменения записи в кэше ARP
//=============================================================================
MRESULT EXPENTRY DlgProcChg(HWND hwnd, ULONG msg, MPARAM mp1, MPARAM mp2)
  {
  struct myarpreq
    {
    struct  sockaddr_in arp_pa;   // protocol address
    struct  sockaddr arp_ha;      // hardware address
    long_int arp_flags;           // flags
    } myarp, myarpdel;
  static struct oarptab *pARP;
  int i, sock;
  char IPaddr[L16], MAC1[L5], MAC2[L5], MAC3[L5], MAC[L13];

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSetWindowText(hwnd, "Change ARP entry");
      pARP = (struct oarptab *)ARPtptr+Sel;

      WinSendDlgItemMsg(hwnd, EF_IP, EM_SETTEXTLIMIT, (MPARAM)L15, L0);
      sprintf(IPaddr, "%s", inet_ntoa(pARP->at_iaddr));
      WinSetDlgItemText(hwnd, EF_IP, IPaddr);

      WinSendDlgItemMsg(hwnd, EF_MAC1, EM_SETTEXTLIMIT, (MPARAM)L4, L0);
      sprintf( MAC1, "%2.2x%2.2x", pARP->at_enaddr[L0], pARP->at_enaddr[L1] );
      WinSetDlgItemText(hwnd, EF_MAC1, MAC1);

      WinSendDlgItemMsg(hwnd, EF_MAC2, EM_SETTEXTLIMIT, (MPARAM)L4, L0);
      sprintf( MAC2, "%2.2x%2.2x", pARP->at_enaddr[L2], pARP->at_enaddr[L3] );
      WinSetDlgItemText(hwnd, EF_MAC2, MAC2);

      WinSendDlgItemMsg(hwnd, EF_MAC3, EM_SETTEXTLIMIT, (MPARAM)L4, L0);
      sprintf( MAC3, "%2.2x%2.2x", pARP->at_enaddr[L4], pARP->at_enaddr[L5] );
      WinSetDlgItemText(hwnd, EF_MAC3, MAC3);

      if ( pARP->at_flags & ATF_PERM ) WinCheckButton(hwnd, CB_PERM, TRUE);
      if ( pARP->at_flags & ATF_PUBL ) WinCheckButton(hwnd, CB_PUBL, TRUE);

      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
        case DID_OK:
          {
          if ( WinQueryDlgItemTextLength(hwnd, EF_IP) < L7 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_IP));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC1) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC1));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC2) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC2));
            return(L0);
            }
          if ( WinQueryDlgItemTextLength(hwnd, EF_MAC3) != L4 )
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC3));
            return(L0);
            }

          memset(&myarp, L0, sizeof(myarp));

          WinQueryDlgItemText(hwnd, EF_IP, L16, IPaddr);
          if ((myarp.arp_pa.sin_addr.s_addr=inet_addr(IPaddr)) == INADDR_NONE)
            {
            WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_IP));
            return(L0);
            }

          WinQueryDlgItemText(hwnd, EF_MAC1, L5, MAC1);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC1[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC1));
              return(L0);
              }
            }
          WinQueryDlgItemText(hwnd, EF_MAC2, L5, MAC2);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC2[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC2));
              return(L0);
              }
            }
          WinQueryDlgItemText(hwnd, EF_MAC3, L5, MAC3);
          for ( i=L0; i<L4; i++ )
            {
            if ( !isxdigit(MAC3[i]) )
              {
              WinSetFocus(HWND_DESKTOP, WinWindowFromID(hwnd, EF_MAC3));
              return(L0);
              }
            }

          strcpy(MAC, MAC1);
          strcat(MAC, MAC2);
          strcat(MAC, MAC3);

          for ( i=L0; i<L6; i++)
            {
            if ( isdigit(MAC[L2*i]) )
              myarp.arp_ha.sa_data[i] = (MAC[L2*i]-'0') << L4;
            else myarp.arp_ha.sa_data[i] = (toupper(MAC[L2*i])-'A'+'\x0a')<<L4;
            if ( isdigit(MAC[L2*i+L1]) )
              myarp.arp_ha.sa_data[i] |= MAC[L2*i+L1]-'0';
            else myarp.arp_ha.sa_data[i] |= toupper(MAC[L2*i+L1])-'A'+'\x0a';
            }
          myarp.arp_pa.sin_family = AF_INET;
          if ( WinQueryButtonCheckstate(hwnd, CB_PERM) )
            myarp.arp_flags |= ATF_PERM;
          if ( WinQueryButtonCheckstate(hwnd, CB_PUBL) )
            myarp.arp_flags |= ATF_PUBL;

          memset(&myarpdel, L0, sizeof(myarpdel));
          myarpdel.arp_pa.sin_family = AF_INET;
          myarpdel.arp_pa.sin_addr.s_addr = pARP->at_iaddr.s_addr;
          memcpy( &myarpdel.arp_ha.sa_data, pARP->at_enaddr,
                  sizeof(pARP->at_enaddr) );
          myarpdel.arp_flags = pARP->at_flags;

          sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
          ioctl(sock, SIOCDARP, (char *)&myarpdel, sizeof(myarpdel));
          ioctl(sock, SIOCSARP, (char *)&myarp, sizeof(myarp));
          soclose(sock);

          break;
          }
        }
      }
      break;
    }
  return (WinDefDlgProc (hwnd,msg,mp1,mp2));
  }