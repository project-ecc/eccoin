/****************************************************************************
** Meta object code from reading C++ file 'signverifymessagedialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.3.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/signverifymessagedialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'signverifymessagedialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.3.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_SignVerifyMessageDialog_t {
    QByteArrayData data[10];
    char stringdata[267];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SignVerifyMessageDialog_t, stringdata) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SignVerifyMessageDialog_t qt_meta_stringdata_SignVerifyMessageDialog = {
    {
QT_MOC_LITERAL(0, 0, 23),
QT_MOC_LITERAL(1, 24, 31),
QT_MOC_LITERAL(2, 56, 0),
QT_MOC_LITERAL(3, 57, 25),
QT_MOC_LITERAL(4, 83, 31),
QT_MOC_LITERAL(5, 115, 33),
QT_MOC_LITERAL(6, 149, 25),
QT_MOC_LITERAL(7, 175, 31),
QT_MOC_LITERAL(8, 207, 33),
QT_MOC_LITERAL(9, 241, 25)
    },
    "SignVerifyMessageDialog\0"
    "on_addressBookButton_SM_clicked\0\0"
    "on_pasteButton_SM_clicked\0"
    "on_signMessageButton_SM_clicked\0"
    "on_copySignatureButton_SM_clicked\0"
    "on_clearButton_SM_clicked\0"
    "on_addressBookButton_VM_clicked\0"
    "on_verifyMessageButton_VM_clicked\0"
    "on_clearButton_VM_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SignVerifyMessageDialog[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   54,    2, 0x08 /* Private */,
       3,    0,   55,    2, 0x08 /* Private */,
       4,    0,   56,    2, 0x08 /* Private */,
       5,    0,   57,    2, 0x08 /* Private */,
       6,    0,   58,    2, 0x08 /* Private */,
       7,    0,   59,    2, 0x08 /* Private */,
       8,    0,   60,    2, 0x08 /* Private */,
       9,    0,   61,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void SignVerifyMessageDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SignVerifyMessageDialog *_t = static_cast<SignVerifyMessageDialog *>(_o);
        switch (_id) {
        case 0: _t->on_addressBookButton_SM_clicked(); break;
        case 1: _t->on_pasteButton_SM_clicked(); break;
        case 2: _t->on_signMessageButton_SM_clicked(); break;
        case 3: _t->on_copySignatureButton_SM_clicked(); break;
        case 4: _t->on_clearButton_SM_clicked(); break;
        case 5: _t->on_addressBookButton_VM_clicked(); break;
        case 6: _t->on_verifyMessageButton_VM_clicked(); break;
        case 7: _t->on_clearButton_VM_clicked(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObject SignVerifyMessageDialog::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_SignVerifyMessageDialog.data,
      qt_meta_data_SignVerifyMessageDialog,  qt_static_metacall, 0, 0}
};


const QMetaObject *SignVerifyMessageDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SignVerifyMessageDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_SignVerifyMessageDialog.stringdata))
        return static_cast<void*>(const_cast< SignVerifyMessageDialog*>(this));
    return QDialog::qt_metacast(_clname);
}

int SignVerifyMessageDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 8;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
