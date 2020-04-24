TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../usr/local/lib/release/ -lpcap
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../usr/local/lib/debug/ -lpcap
else:unix: LIBS += -L$$PWD/../../usr/local/lib/ -lpcap

INCLUDEPATH += $$PWD/../../usr/include
DEPENDPATH += $$PWD/../../usr/include
