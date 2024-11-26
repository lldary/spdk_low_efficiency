
from s_tui.sources.rapl_power_source import RaplPowerSource
import time
source = RaplPowerSource()
number = 0
with open("text_1.txt","a") as file:
    file.write("\t时间" + "\t" + "功耗" + "\n")
    while True:
        avg_power = 0
        for i in range(1,610):
            source.update()
            summary = dict(source.get_sensors_summary())
        
            cpu_power_total = str(sum(list(map(float, [summary[key] for key in summary.keys() if key.startswith('package')]))))
            avg_power += float(cpu_power_total)
            time.sleep(0.1)
        # print('\r' + "当前时间" + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + " CPU功耗：" + str(avg_power/60), end='', flush=True)
        print('\r' + str(number) + ": time:" + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + " power:" + str(round(avg_power/610, 2)))
        number += 1
        file.write('\t' + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + "\t" + str(avg_power/610) + "\n")