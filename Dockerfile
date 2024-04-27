FROM swipl as backend
RUN apt-get update
RUN apt-get install vim -y
RUN echo "set number" > ~/.vimrc
RUN echo "set incsearch" >> ~/.vimrc
RUN echo "syntax on" >> ~/.vimrc
FROM python:3.12
RUN pip install flask
WORKDIR /queryengine
COPY . .
ENV FLASK_APP=main.py
EXPOSE 5000
COPY --from=backend . /
CMD ["flask", "run", "--host", "0.0.0.0"]