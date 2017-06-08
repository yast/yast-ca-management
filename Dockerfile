FROM yastdevel/ruby:sle12-sp2
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  perl-Date-Calc \
  perl-URI \
  perl-X500-DN \
  perl-XML-Writer \
  perl-camgm
COPY . /usr/src/app
