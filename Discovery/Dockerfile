FROM openjdk:8-jdk
EXPOSE  8761
WORKDIR /app

# Copy maven executable to the image
COPY mvnw .
COPY .mvn .mvn



# Copy the pom.xml file
COPY ./pom.xml ./pom.xml

RUN chmod 755 mvnw
RUN ./mvnw dependency:go-offline -B


# Copy the project source
COPY ./src ./src


RUN ./mvnw  package
#RUN ls -al
ENTRYPOINT ["java","-jar","target/Discovery-0.0.1-SNAPSHOT.jar"]