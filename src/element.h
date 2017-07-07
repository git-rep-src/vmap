#ifndef ELEMENT_H
#define ELEMENT_H

#include "ui.h"

#include <string>
#include <vector>

namespace Ui {
class Element;
}

class Element : public QWidget
{
    Q_OBJECT

public:
    explicit Element(int number, std::string published,
                     std::string title, float score,
                     std::string description, std::string id,
                     std::string vector, std::vector<std::string> cpe,
                     std::vector<std::string> references, std::string sourcedata,
                     QWidget *parent);
    ~Element();

private:
    Ui::Element *ui;

private slots:
    void process(std::string &published, std::string &title,
                 std::string &vector, std::vector<std::string> &cpe,
                 std::vector<std::string> &references, bool is_exploit);
};

#endif // ELEMENT_H
