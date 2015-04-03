/****************************************************************************
** Meta object code from reading C++ file 'rpcconsole.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.3.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/rpcconsole.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'rpcconsole.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.3.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_RPCConsole_t {
    QByteArrayData data[21];
    char stringdata[280];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_RPCConsole_t, stringdata) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_RPCConsole_t qt_meta_stringdata_RPCConsole = {
    {
QT_MOC_LITERAL(0, 0, 10),
QT_MOC_LITERAL(1, 11, 12),
QT_MOC_LITERAL(2, 24, 0),
QT_MOC_LITERAL(3, 25, 10),
QT_MOC_LITERAL(4, 36, 7),
QT_MOC_LITERAL(5, 44, 25),
QT_MOC_LITERAL(6, 70, 27),
QT_MOC_LITERAL(7, 98, 5),
QT_MOC_LITERAL(8, 104, 33),
QT_MOC_LITERAL(9, 138, 30),
QT_MOC_LITERAL(10, 169, 5),
QT_MOC_LITERAL(11, 175, 7),
QT_MOC_LITERAL(12, 183, 8),
QT_MOC_LITERAL(13, 192, 4),
QT_MOC_LITERAL(14, 197, 17),
QT_MOC_LITERAL(15, 215, 5),
QT_MOC_LITERAL(16, 221, 12),
QT_MOC_LITERAL(17, 234, 12),
QT_MOC_LITERAL(18, 247, 13),
QT_MOC_LITERAL(19, 261, 6),
QT_MOC_LITERAL(20, 268, 11)
    },
    "RPCConsole\0stopExecutor\0\0cmdRequest\0"
    "command\0on_lineEdit_returnPressed\0"
    "on_tabWidget_currentChanged\0index\0"
    "on_openDebugLogfileButton_clicked\0"
    "on_showCLOptionsButton_clicked\0clear\0"
    "message\0category\0html\0setNumConnections\0"
    "count\0setNumBlocks\0countOfPeers\0"
    "browseHistory\0offset\0scrollToEnd"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_RPCConsole[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   79,    2, 0x06 /* Public */,
       3,    1,   80,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    0,   83,    2, 0x08 /* Private */,
       6,    1,   84,    2, 0x08 /* Private */,
       8,    0,   87,    2, 0x08 /* Private */,
       9,    0,   88,    2, 0x08 /* Private */,
      10,    0,   89,    2, 0x0a /* Public */,
      11,    3,   90,    2, 0x0a /* Public */,
      11,    2,   97,    2, 0x2a /* Public | MethodCloned */,
      14,    1,  102,    2, 0x0a /* Public */,
      16,    2,  105,    2, 0x0a /* Public */,
      18,    1,  110,    2, 0x0a /* Public */,
      20,    0,  113,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    4,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, QMetaType::QString, QMetaType::Bool,   12,   11,   13,
    QMetaType::Void, QMetaType::Int, QMetaType::QString,   12,   11,
    QMetaType::Void, QMetaType::Int,   15,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,   15,   17,
    QMetaType::Void, QMetaType::Int,   19,
    QMetaType::Void,

       0        // eod
};

void RPCConsole::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        RPCConsole *_t = static_cast<RPCConsole *>(_o);
        switch (_id) {
        case 0: _t->stopExecutor(); break;
        case 1: _t->cmdRequest((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: _t->on_lineEdit_returnPressed(); break;
        case 3: _t->on_tabWidget_currentChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->on_openDebugLogfileButton_clicked(); break;
        case 5: _t->on_showCLOptionsButton_clicked(); break;
        case 6: _t->clear(); break;
        case 7: _t->message((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3]))); break;
        case 8: _t->message((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 9: _t->setNumConnections((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->setNumBlocks((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 11: _t->browseHistory((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 12: _t->scrollToEnd(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        void **func = reinterpret_cast<void **>(_a[1]);
        {
            typedef void (RPCConsole::*_t)();
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&RPCConsole::stopExecutor)) {
                *result = 0;
            }
        }
        {
            typedef void (RPCConsole::*_t)(const QString & );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&RPCConsole::cmdRequest)) {
                *result = 1;
            }
        }
    }
}

const QMetaObject RPCConsole::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_RPCConsole.data,
      qt_meta_data_RPCConsole,  qt_static_metacall, 0, 0}
};


const QMetaObject *RPCConsole::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RPCConsole::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_RPCConsole.stringdata))
        return static_cast<void*>(const_cast< RPCConsole*>(this));
    return QDialog::qt_metacast(_clname);
}

int RPCConsole::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 13;
    }
    return _id;
}

// SIGNAL 0
void RPCConsole::stopExecutor()
{
    QMetaObject::activate(this, &staticMetaObject, 0, 0);
}

// SIGNAL 1
void RPCConsole::cmdRequest(const QString & _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_END_MOC_NAMESPACE
