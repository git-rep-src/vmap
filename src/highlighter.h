#ifndef HIGHLIGHTER_H
#define HIGHLIGHTER_H

#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QRegularExpression>

class QTextDocument;

class Highlighter : public QSyntaxHighlighter
{
    Q_OBJECT

public:
    Highlighter(QTextDocument *parent = 0);

protected:
    void highlightBlock(const QString &str) override;

private:
    struct HighlightingRule
    {
        QRegularExpression pattern;
        QTextCharFormat format;
    };
    QVector<HighlightingRule> rules;

    QRegularExpression start_comment;
    QRegularExpression end_comment;

    QTextCharFormat function;
    QTextCharFormat keyword;
    QTextCharFormat number;
    QTextCharFormat sign;
    QTextCharFormat quote;
    QTextCharFormat hex;
    QTextCharFormat comment;
};

#endif // HIGHLIGHTER_H
