#start by pulling the python image
FROM python:3.8-alpine

#copy the requirements file into the image
COPY ./requirements.txt /app/requirements.txt

#switching working directory
WORKDIR /app

# install dependencies and packages in the requirements file
RUN pip install -r requirements.txt

