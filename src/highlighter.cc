#include "highlighter.h"

Highlighter::Highlighter(QTextDocument *parent) :
    QSyntaxHighlighter(parent)
{
    HighlightingRule rule;
    QStringList patterns;

    function.setForeground(Qt::white);
    rule.pattern = QRegularExpression("\\b[A-Za-z0-9_]+(?=\\()");
    rule.format = function;
    rules.append(rule);

    keyword.setFontWeight(QFont::Bold);
    keyword.setForeground(QColor(0, 127, 127));
    patterns << "\\bclass\\b" << "\\bnamespace\\b" << "\\bdef\\b" << "\\bend\\b"
             << "\\btemplate\\b" << "\\bvoid\\b" << "\\bchar\\b" << "\\bshort\\b"
             << "\\blong\\b" << "\\bint\\b" << "\\bfloat\\b" << "\\bdouble\\b"
             << "\\bbool\\b" << "\\bstruct\\b" << "\\benum\\b" << "\\bunion\\b";
    foreach (const QString &pattern, patterns) {
        rule.pattern = QRegularExpression(pattern);
        rule.format = keyword;
        rules.append(rule);
    }
    keyword.setForeground(QColor(0, 95, 0));
    patterns.clear();
    patterns << "\\bexplicit\\b" << "\\bpublic\\b" << "\\bprivate\\b" << "\\bvirtual\\b"
             << "\\bprotected\\b" << "\\bsignals\\b" << "\\bslots\\b";
    foreach (const QString &pattern, patterns) {
        rule.pattern = QRegularExpression(pattern);
        rule.format = keyword;
        rules.append(rule);
    }
    keyword.setForeground(QColor(70, 70, 70));
    patterns.clear();
    patterns << "\\binclude\\b" << "\\brequire\\b" << "\\bimport\\b" << "\\bfrom\\b"
             << "\\bextern\\b" << "\\bconst\\b" << "\\bstatic\\b" << "\\bfriend\\b"
             << "\\bsigned\\b" << "\\bunsigned\\b" << "\\btypedef\\b" << "\\bvolatile\\b"
             << "\\binline\\b";
    foreach (const QString &pattern, patterns) {
        rule.pattern = QRegularExpression(pattern);
        rule.format = keyword;
        rules.append(rule);
    }
    keyword.setFontWeight(QFont::Medium);
    keyword.setForeground(QColor(0, 127, 127));
    patterns.clear();
    patterns << "\\bif\\b" << "\\belse\\b" << "\\belse if\\b"
             << "\\belif\\b" << "\\bfi\\b" << "\\bfor\\b"
             << "\\bdo\\b" << "\\bwhile\\b" << "\\bbegin\\b"
             << "\\brescue\\b" << "\\bensure\\b" << "\\beach\\b"
             << "\\bdone\\b" << "\\breturn\\b";
    foreach (const QString &pattern, patterns) {
        rule.pattern = QRegularExpression(pattern);
        rule.format = keyword;
        rules.append(rule);
    }

    number.setForeground(Qt::white);
    rule.pattern = QRegularExpression("[0-9]");
    rule.format = number;
    rules.append(rule);

    sign.setFontWeight(QFont::Bold);
    sign.setForeground(Qt::white);
    rule.pattern = QRegularExpression("[=<>{}()|]");
    rule.format = sign;
    rules.append(rule);

    quote.setForeground(Qt::darkGray);
    rule.pattern = QRegularExpression("(\".*\")|(\'.*\')");
    rule.format = quote;
    rules.append(rule);

    hex.setForeground(Qt::red);
    rule.pattern = QRegularExpression("\\\\[xX][0-9a-fA-F]+");
    rule.format = hex;
    rules.append(rule);

    comment.setFontItalic(true);
    comment.setForeground(QColor(61, 66, 77));
    rule.pattern = QRegularExpression("(//[^\n]*)|(#[^\n]*)");
    rule.format = comment;
    rules.append(rule);

    start_comment = QRegularExpression("(/\\*)|(<!--)"); // TODO: PERL
    end_comment = QRegularExpression("(\\*/)|(-->)");
}

void Highlighter::highlightBlock(const QString &str)
{
    foreach (const HighlightingRule &rule, rules) {
        QRegularExpressionMatchIterator it = rule.pattern.globalMatch(str);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }
    setCurrentBlockState(0);

    int start_index = 0;
    if (previousBlockState() != 1)
        start_index = str.indexOf(start_comment);

    while (start_index >= 0) {
        QRegularExpressionMatch match = end_comment.match(str, start_index);
        int end_index = match.capturedStart();
        int length = 0;
        if (end_index == -1) {
            setCurrentBlockState(1);
            length = str.length() - start_index;
        } else {
            length = end_index - start_index
                            + match.capturedLength();
        }
        setFormat(start_index, length, comment);
        start_index = str.indexOf(start_comment, start_index + length);
    }
}
