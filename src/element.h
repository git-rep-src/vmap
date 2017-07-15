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
                     std::vector<std::string> cve, std::string cvss,
                     std::vector<std::string> cpe, std::string href,
                     std::string source, QWidget *parent);
    ~Element();

signals:
    void send_status_signal(QString status);

private:
    Ui::Element *ui;

private slots:
    void process(std::string &published, std::string &title,
                 std::string &description, std::vector<std::string> &cve,
                 std::string &cvss, std::vector<std::string> &cpe,
                 std::string &href, std::string &source,
                 bool is_exploitdb, bool is_packetstorm);
    bool save(std::string id, const std::string &source);
};

#endif // ELEMENT_H
