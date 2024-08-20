FROM ruby:3.3
RUN gem install bundler && mkdir -p /usr/src/app
COPY Gemfile* /usr/src/app
WORKDIR /usr/src/app
RUN bundle install
COPY . /usr/src/app
ENTRYPOINT ["bundle", "exec"]
CMD ["rake", "spec"]
