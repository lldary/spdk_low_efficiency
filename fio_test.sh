#!/bin/bash
# 用来跑测试脚本
# cpufreq-set -c 12 -f 2000000
# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/write_128k_1_$queue_depth.fio --output=../spdk_int_poll_result_write_128k_$queue_depth.txt"

#     LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/write_128k_1_$queue_depth.fio --output=../spdk_int_poll_result_write_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/read_128k_1_$queue_depth.fio --output=../spdk_int_poll_result_read_128k_$queue_depth.txt"

#     LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/read_128k_1_$queue_depth.fio --output=../spdk_int_poll_result_read_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done


# cpufreq-set -c 12 -f 2300000

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/randwrite_4k_1_$queue_depth.fio --output=../spdk_2.3GHz_result_randwrite_4k_$queue_depth.txt"

#     LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/randwrite_4k_1_$queue_depth.fio --output=../spdk_2.3GHz_result_randwrite_4k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# cpufreq-set -g powersave

# cpufreq-set -c 12 -f 1000000

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/randwrite_4k_1_$queue_depth.fio --output=../spdk_1GHz_result_randwrite_4k_$queue_depth.txt"

#     LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/randwrite_4k_1_$queue_depth.fio --output=../spdk_1GHz_result_randwrite_4k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# cpufreq-set -g powersave

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/read_128k_1_$queue_depth.fio --output=../spdk_origin_result_read_128k_$queue_depth.txt"

#     LD_PRELOAD=./build/fio/spdk_nvme ../fio/fio ../test_fio/read_128k_1_$queue_depth.fio --output=../spdk_origin_result_read_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# PCI_ALLOWED="0000:64:00.0" scripts/setup.sh reset

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     echo "sudo ../fio/fio -ioengine=libaio -bs=128k -direct=1 -thread -rw=write -filename=/dev/nvme2n1 -name=（BS 4KB read test） -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../libaio_result_write_128k_$queue_depth.txt"
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "sudo ../fio/fio -ioengine=libaio -bs=128k -direct=1 -thread -rw=write -filename=/dev/nvme2n1 -name=（BS 4KB read test） -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../libaio_result_write_128k_$queue_depth.txt"
    
#     ../fio/fio -ioengine=libaio -bs=128k -direct=1 -thread -rw=write -filename=/dev/nvme2n1 -name="BS 4KB read test" -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../libaio_result_write_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "sudo ../fio/fio -ioengine=libaio -bs=128k -direct=1 -thread -rw=read -filename=/dev/nvme2n1 -name=（BS 128KB read test） -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../libaio_result_read_128k_$queue_depth.txt"
    
#     ../fio/fio -ioengine=libaio -bs=128k -direct=1 -thread -rw=read -filename=/dev/nvme2n1 -name="BS 128KB read test" -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../libaio_result_read_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# for queue_depth in {1,2,4,8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "sudo ../fio/fio -ioengine=io_uring -sqthread_poll=1 -bs=128k -direct=1 -thread -rw=write -filename=/dev/nvme2n1 -name=（BS 128KB read test） -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../io_uring_sqpoll_result_write_128k_$queue_depth.txt"
    
#     ../fio/fio -ioengine=io_uring -sqthread_poll=1 -bs=128k -direct=1 -thread -rw=write -filename=/dev/nvme2n1 -name="BS 128KB read test" -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../io_uring_sqpoll_result_write_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done

# for queue_depth in {8,16,32,64,128}
# do
#     # 定义current_time 变量，格式化时间
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     sleep 300
#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo $current_time

#     echo "sudo ../fio/fio -ioengine=io_uring -sqthread_poll=1 -bs=128k -direct=1 -thread -rw=read -filename=/dev/nvme2n1 -name=（BS 128KB read test） -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../io_uring_sqpoll_result_read_128k_$queue_depth.txt"
    
#     ../fio/fio -ioengine=io_uring -sqthread_poll=1 -bs=128k -direct=1 -thread -rw=read -filename=/dev/nvme2n1 -name="BS 128KB read test" -size=1G -iodepth=$queue_depth -runtime=1200 -group_reporting -time_based --numjobs=1 --output=../io_uring_sqpoll_result_read_128k_$queue_depth.txt

#     current_time=`date +"%Y-%m-%d %H:%M:%S"`
#     echo ""
#     echo $current_time
#     sleep 60
# done