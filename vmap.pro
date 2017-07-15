QT += core gui widgets

unix {
    CONFIG += link_pkgconfig c++11
    LIBS += -L/usr/lib/ -lcrypto -lssl
}

TARGET = vmap
TEMPLATE = app

SOURCES += src/main.cc \
           src/vmap.cc \
           src/finder.cc \
           src/view.cc \
           src/element.cc \
           src/highlighter.cc \
           src/ssl_socket.cc \
           src/json.cc

HEADERS  += src/vmap.h \
            src/finder.h \
            src/view.h \
            src/element.h \
            src/highlighter.h \
            src/ssl_socket.h \
            src/custompushbutton.h \
            src/ui.h

RESOURCES = resources.qrc

RC_FILE = resources/images/global/icon.rc

OBJECTS_DIR = .build/.obj
MOC_DIR = .build/.moc
RCC_DIR = .build/.rcc
