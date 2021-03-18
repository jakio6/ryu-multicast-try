#!/bin/sh


# 使用docker容器运行ryu.
# ```
# docker build -t . ryu
# sh run.sh
# ```

docker run -ti --rm --net=host -v $(pwd):/root/ryu_src ryu:latest /bin/bash
