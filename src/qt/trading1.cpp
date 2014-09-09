#include "trading1.h"
#include "ui_tradingwindow.h"


TradingWindow::TradingWindow(QWidget *parent) :
    QWidget(parent), ui(new Ui::TradingWindow)
{
    ui->setupUi(this);
}
