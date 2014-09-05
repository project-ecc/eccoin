#ifndef TRADING1_H
#define TRADING1_H

#include <QtGui>
#include <C:\Qt\4.8.6\include\QtNetwork\QtNetwork>
#include "clientmodel.h"

namespace Ui {
class TradingWindow;
}

class TradingWindow : public QWidget {
    Q_OBJECT

  public:
     TradingWindow(QWidget *parent = 0);
     void setModel(ClientModel *model);

  private:
   Ui::TradingWindow *ui;
   ClientModel *model;


private slots:

};


#endif // TRADING1_H
