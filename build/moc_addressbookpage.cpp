/****************************************************************************
** Meta object code from reading C++ file 'addressbookpage.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.3.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/addressbookpage.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'addressbookpage.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.3.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_AddressBookPage_t {
    QByteArrayData data[23];
    char stringdata[326];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_AddressBookPage_t, stringdata) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_AddressBookPage_t qt_meta_stringdata_AddressBookPage = {
    {
QT_MOC_LITERAL(0, 0, 15),
QT_MOC_LITERAL(1, 16, 11),
QT_MOC_LITERAL(2, 28, 0),
QT_MOC_LITERAL(3, 29, 4),
QT_MOC_LITERAL(4, 34, 13),
QT_MOC_LITERAL(5, 48, 4),
QT_MOC_LITERAL(6, 53, 6),
QT_MOC_LITERAL(7, 60, 13),
QT_MOC_LITERAL(8, 74, 23),
QT_MOC_LITERAL(9, 98, 27),
QT_MOC_LITERAL(10, 126, 26),
QT_MOC_LITERAL(11, 153, 22),
QT_MOC_LITERAL(12, 176, 24),
QT_MOC_LITERAL(13, 201, 16),
QT_MOC_LITERAL(14, 218, 21),
QT_MOC_LITERAL(15, 240, 14),
QT_MOC_LITERAL(16, 255, 5),
QT_MOC_LITERAL(17, 261, 17),
QT_MOC_LITERAL(18, 279, 12),
QT_MOC_LITERAL(19, 292, 16),
QT_MOC_LITERAL(20, 309, 6),
QT_MOC_LITERAL(21, 316, 5),
QT_MOC_LITERAL(22, 322, 3)
    },
    "AddressBookPage\0signMessage\0\0addr\0"
    "verifyMessage\0done\0retval\0exportClicked\0"
    "on_deleteButton_clicked\0"
    "on_newAddressButton_clicked\0"
    "on_copyToClipboard_clicked\0"
    "on_signMessage_clicked\0on_verifyMessage_clicked\0"
    "selectionChanged\0on_showQRCode_clicked\0"
    "contextualMenu\0point\0onCopyLabelAction\0"
    "onEditAction\0selectNewAddress\0parent\0"
    "begin\0end"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_AddressBookPage[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
      15,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   89,    2, 0x06 /* Public */,
       4,    1,   92,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   95,    2, 0x0a /* Public */,
       7,    0,   98,    2, 0x0a /* Public */,
       8,    0,   99,    2, 0x08 /* Private */,
       9,    0,  100,    2, 0x08 /* Private */,
      10,    0,  101,    2, 0x08 /* Private */,
      11,    0,  102,    2, 0x08 /* Private */,
      12,    0,  103,    2, 0x08 /* Private */,
      13,    0,  104,    2, 0x08 /* Private */,
      14,    0,  105,    2, 0x08 /* Private */,
      15,    1,  106,    2, 0x08 /* Private */,
      17,    0,  109,    2, 0x08 /* Private */,
      18,    0,  110,    2, 0x08 /* Private */,
      19,    3,  111,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    3,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,   16,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QModelIndex, QMetaType::Int, QMetaType::Int,   20,   21,   22,

       0        // eod
};

void AddressBookPage::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        AddressBookPage *_t = static_cast<AddressBookPage *>(_o);
        switch (_id) {
        case 0: _t->signMessage((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 1: _t->verifyMessage((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 2: _t->done((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->exportClicked(); break;
        case 4: _t->on_deleteButton_clicked(); break;
        case 5: _t->on_newAddressButton_clicked(); break;
        case 6: _t->on_copyToClipboard_clicked(); break;
        case 7: _t->on_signMessage_clicked(); break;
        case 8: _t->on_verifyMessage_clicked(); break;
        case 9: _t->selectionChanged(); break;
        case 10: _t->on_showQRCode_clicked(); break;
        case 11: _t->contextualMenu((*reinterpret_cast< const QPoint(*)>(_a[1]))); break;
        case 12: _t->onCopyLabelAction(); break;
        case 13: _t->onEditAction(); break;
        case 14: _t->selectNewAddress((*reinterpret_cast< const QModelIndex(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        void **func = reinterpret_cast<void **>(_a[1]);
        {
            typedef void (AddressBookPage::*_t)(QString );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&AddressBookPage::signMessage)) {
                *result = 0;
            }
        }
        {
            typedef void (AddressBookPage::*_t)(QString );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&AddressBookPage::verifyMessage)) {
                *result = 1;
            }
        }
    }
}

const QMetaObject AddressBookPage::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_AddressBookPage.data,
      qt_meta_data_AddressBookPage,  qt_static_metacall, 0, 0}
};


const QMetaObject *AddressBookPage::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AddressBookPage::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_AddressBookPage.stringdata))
        return static_cast<void*>(const_cast< AddressBookPage*>(this));
    return QDialog::qt_metacast(_clname);
}

int AddressBookPage::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 15)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 15;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 15)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 15;
    }
    return _id;
}

// SIGNAL 0
void AddressBookPage::signMessage(QString _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void AddressBookPage::verifyMessage(QString _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_END_MOC_NAMESPACE
