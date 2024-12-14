
from s_tui.sources.rapl_power_source import RaplPowerSource
import time
source = RaplPowerSource()
number = 0
frequency = 0.0001
with open("text_1.txt","a") as file:
    file.write("\t时间" + "\t" + "功耗" + "\n")
    while True:
        avg_power = 0
        len = int(60 / frequency)
        for i in range(1,len):
            source.update()
            summary = dict(source.get_sensors_summary())
        
            cpu_power_total = str(sum(list(map(float, [summary[key] for key in summary.keys() if key.startswith('package')]))))
            print(cpu_power_total)
            avg_power += float(cpu_power_total)
            if cpu_power_total > 500:
                exit()
            time.sleep(frequency)
        # print('\r' + "当前时间" + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + " CPU功耗：" + str(avg_power/60), end='', flush=True)
        print('\r' + str(number) + ": time:" + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + " power:" + str(round(avg_power * frequency / 60, 2)))
        number += 1
        file.write('\t' + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + "\t" + str(avg_power * frequency / 60) + "\n")