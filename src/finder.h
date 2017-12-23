#ifndef FINDER_H
#define FINDER_H

#include "ui.h"

#include <string>
#include <vector>

namespace Ui {
class Finder;
}

class Finder : public QWidget
{
    Q_OBJECT

public:
    explicit Finder(QWidget *parent);
    ~Finder();

public slots:
    void set_counter(int offset, int n_total);

signals:
    void request_signal(const std::string &url, const std::string &name,
                        const std::string &version, int max,
                        bool has_offset);
    void status_signal(const std::string &status);

private:
    Ui::Finder *ui;

    bool is_blocked;
    bool has_error;

    QString last_dir;

    std::string query;
    std::string vector;
    std::string type;
    std::string score;
    std::string date;
    std::string order;
    std::string max;
    std::string url;

private slots:
    void build_request(bool has_offset = false);
    void set_query();
    void set_vector();
    void set_type();
    void set_score();
    void set_date();
    void set_order();
    void set_max();
#ifdef NMAP
    void open_file();
    bool xml(std::vector<std::string> *terms);
#endif
};

#endif // FINDER_H
