#ifndef ELEMENT_H
#define ELEMENT_H

#include "ui.h"

#include <string>

namespace Ui {
class Element;
}

class Element : public QWidget
{
    Q_OBJECT

public:
    explicit Element(std::string published, std::string title,
                     float score, std::string description,
                     std::string id, std::string sourcedata,
                     QWidget *parent);
    ~Element();

private:
    Ui::Element *ui;
};

#endif // ELEMENT_H
