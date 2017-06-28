#include "vmap.h"

#include <QApplication>
#include <QFile>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    
    QFile file(":/style-default");
    file.open(QFile::ReadOnly);
    QString stylesheet = QLatin1String(file.readAll());
    file.close();
    qApp->setStyleSheet(stylesheet);
    
    Vmap vmap;
    vmap.showFullScreen();

    return a.exec();
}
