FROM ubuntu:16.04

ARG USERNAME=dapi
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
  && useradd --uid $USER_UID --gid $USER_GID \
  --create-home --shell /bin/bash $USERNAME

RUN apt-get update && apt-get install -y \
  software-properties-common locales

RUN add-apt-repository ppa:ubuntu-toolchain-r/test \
  && apt-get update && apt-get install -y \
  git gcc-7 g++-7 gdb make qemu python3 \
  && apt-get clean

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 50 \
  --slave /usr/bin/g++ g++ /usr/bin/g++-7

RUN locale-gen en_US.UTF-8

USER $USERNAME

RUN echo "source /workspaces/dapi-pintos/activate" >> ~/.bashrc

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

CMD ["/bin/bash"]
