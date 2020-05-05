#include "vmap.h"

#include <QApplication>
#include <QFile>

#include <string>
#include <iostream>

int main(int argc, char *argv[])
{
    if ((argc > 1) &&
        ((argv[1] == std::string("-h")) ||
         (argv[1] == std::string("--help")) ||
         (argv[1] == std::string("-v")) ||
         (argv[1] == std::string("--version")))) {
        std::cout << std::endl;
        std::cout << "A Vulnerability-Exploit desktop finder (https://gitlab.com/git-rep/vmap)" << std::endl;
        std::cout << "Version 0.4.1" << std::endl;
        std::cout << std::endl;
        return 0;
    }

    QApplication a(argc, argv);

    QFile file(":/style-default");
    if (file.open(QFile::ReadOnly)) {
        QString stylesheet = QLatin1String(file.readAll());
        file.close();
        qApp->setStyleSheet(stylesheet);
    }

    Vmap vmap;
    vmap.showFullScreen();

    return a.exec();
}
