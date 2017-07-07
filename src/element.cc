#include "element.h"

Element::Element(int number, std::string published,
                 std::string title, float score,
                 std::string description, std::string id,
                 std::string vector, std::vector<std::string> cpe,
                 std::vector<std::string> references, std::string sourcedata,
                 QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Element)
{
    ui->setupUi(this);

    bool is_exploit = (sourcedata != "");

    process(published, title, vector, cpe, references, is_exploit);

    ui->number_label->setText(QString("%1").arg(number, 5, 10, QChar('0')));
    ui->published_label->setText(QString::fromStdString(published));
    ui->title_label->setText(QString::fromStdString(title));
    if (score >= 7)
        ui->score_label->setProperty("type", "score-high");
    else if ((score >= 4) && (score < 7))
        ui->score_label->setProperty("type", "score-medium");
    ui->score_label->setText(QString::number(score));
    ui->description_label->setText(QString::fromStdString(description));
    ui->id_label->setText(ui->id_label->text() + QString::fromStdString(id));
    ui->cvss_data_label->setText(QString::fromStdString(vector));
    ui->source_textedit->setPlainText(QString::fromStdString(sourcedata));

    QObject::connect(ui->details_button, &QPushButton::pressed, [=] {
        ui->description_label->setVisible(!ui->description_label->isVisible());
        ui->id_label->setVisible(!ui->id_label->isVisible());
        if (ui->description_label->isVisible())
            ui->details_button->setIcon(QIcon(":/icon-less"));
        else
            ui->details_button->setIcon(QIcon(":/icon-more"));
        if (is_exploit) {
            ui->source_label->setVisible(!ui->source_label->isVisible());
            ui->source_save_button->setVisible(!ui->source_save_button->isVisible());
            ui->source_textedit->setVisible(!ui->source_textedit->isVisible());
        } else {
            ui->cvss_label->setVisible(!ui->cvss_label->isVisible());
            ui->cvss_data_label->setVisible(!ui->cvss_data_label->isVisible());
            ui->cpe_vendor_label->setVisible(!ui->cpe_vendor_label->isVisible());
            ui->cpe_product_label->setVisible(!ui->cpe_product_label->isVisible());
            ui->cpe_version_label->setVisible(!ui->cpe_version_label->isVisible());
            ui->reference_label->setVisible(!ui->reference_label->isVisible());
        }
    });
}

Element::~Element()
{
    delete ui;
}

void Element::process(std::string &published, std::string &title,
                      std::string &vector, std::vector<std::string> &cpe,
                      std::vector<std::string> &references, bool is_exploit)
{
    std::size_t i;
    std::size_t n;

    if ((n =published.std::string::find("T")) != std::string::npos)
        published.std::string::erase(n, published.std::string::size());

    if (title.std::string::size() >= (size_t)ui->title_label->width())
        title.std::string::replace((ui->title_label->width() - 3),
                                   (title.std::string::size() - (ui->title_label->width() - 3)),
                                   "...");

    if (is_exploit) {
        bool has_quotes = false;
        for (i = 0; i < title.size(); i++) {
            if (title[i] == '<')
                title.std::string::replace(i, 1, "&lt;");
            else if (title[i] == '>')
                title.std::string::replace(i, 1, "&gt;");
        }
        if ((n = title.std::string::rfind("'")) != std::string::npos) {
            title.std::string::insert((n + 1), "<span style=color:#646464 style=background-color:#23262b> ");
            title.std::string::insert(title.std::string::size(), " </span>");
            title.std::string::replace(n, 1, " ");
            title.std::string::replace(title.std::string::find("'"), 1, " ");
            has_quotes = true;
        }
        if ((n = title.std::string::rfind(" - ")) != std::string::npos) {
            if (!has_quotes) {
                title.std::string::insert((n + 1), "<span style=color:#646464 style=background-color:#23262b> ");
                title.std::string::insert(title.std::string::size(), " </span>");
            }
            title.std::string::replace(title.std::string::rfind(" - "), 2, " ");
        }
    } else {
        std::string buf;

        if ((n = vector.std::string::find("AV:")) != std::string::npos)
            vector.std::string::erase(n, 3);
        if ((n = vector.std::string::find("/AC:")) != std::string::npos)
            vector.std::string::replace(n, 4, "<hr>");
        if ((n = vector.std::string::find("/Au:")) != std::string::npos)
            vector.std::string::erase(n, (vector.std::string::find("/C") - n));
        if ((n = vector.std::string::find("/C:")) != std::string::npos)
            vector.std::string::replace(n, 3, "<hr>");
        if ((n = vector.std::string::find("/I:")) != std::string::npos)
            vector.std::string::replace(n, 3, "<hr>");
        if ((n = vector.std::string::find("/A:")) != std::string::npos)
            vector.std::string::replace(n, 3, "<hr>");
        if ((n = vector.std::string::rfind("/")) != std::string::npos)
            vector.std::string::erase(n, 1);

        for (i = 0; i < cpe.size(); i++) {
            buf.clear();
            if ((((n = cpe[i].std::string::find("cpe:/a:")) != std::string::npos) ||
                 ((n = cpe[i].std::string::find("cpe:/h:")) != std::string::npos) ||
                 ((n = cpe[i].std::string::find("cpe:/o:")) != std::string::npos))) {
                  cpe[i].std::string::erase(0, 7);
                  buf.append(cpe[i].std::string::substr(0, cpe[i].std::string::find(":")));
                  if (i != (cpe.size() - 1))
                      buf.append("<hr>");
                  ui->cpe_vendor_label->setText(ui->cpe_vendor_label->text() + QString::fromStdString(buf));
            }
            buf.clear();
            if ((n = cpe[i].std::string::find(":")) != std::string::npos) {
                buf.append(cpe[i].std::string::substr((n + 1), (cpe[i].std::string::rfind(":") - (n + 1))));
                if (i != (cpe.size() - 1))
                    buf.append("<hr>");
                ui->cpe_product_label->setText(ui->cpe_product_label->text() + QString::fromStdString(buf));
            }
            buf.clear();
            if ((n = cpe[i].std::string::rfind(":")) != std::string::npos) {
                buf.append(cpe[i].std::string::substr((n + 1), cpe[i].size()));
                if (i != (cpe.size() - 1))
                    buf.append("<hr>");
                ui->cpe_version_label->setText(ui->cpe_version_label->text() + QString::fromStdString(buf));
            }
        }
        for (i = 0; i < references.size(); i++) {
            if ((n = references[i].std::string::find("www.")) != std::string::npos)
                references[i].std::string::erase(n, 4);
            if (((n = references[i].std::string::find("http://")) == std::string::npos) &&
                ((n = references[i].std::string::find("https://")) == std::string::npos))
                references[i].std::string::insert(0, "http://");
            if (i != (references.size() - 1))
                references[i].std::string::insert(references[i].size(), "<br>");
            ui->reference_label->setText(ui->reference_label->text() + QString::fromStdString(references[i]));
        }
    }
}
