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
    explicit Element(bool has_cpe , bool has_source, QWidget *parent);
    ~Element();

public slots:
    void set_number(int number);
    void set_published(std::string published);
    void set_title(std::string title, bool has_quotes, bool has_dash);
    void set_score(float score);
    void set_description_cve(std::string description, std::vector<std::string> cve, bool is_exploitdb);
    void set_id(std::string id);
    void set_cvss(std::string cvss);
    void set_cpe(std::vector<std::string> cpe);
    void set_href(std::string href);
    void set_source(std::string source, bool is_packetstorm);

signals:
    void send_status_signal(QString status);

private:
    Ui::Element *ui;

private slots:
    bool save_source();
};

#endif // ELEMENT_H
