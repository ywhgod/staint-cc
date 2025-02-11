import gym
import numpy as np
from redis.client import Redis
from gym import spaces
from typing import Optional, Union
# from gym.utils import seeding


class RlccEnvR(gym.Env):
    """
    ### Description

    This environment is for reinforcement learning based congestion control algorithm research
    This environment relays on mininet and redis, you need install them first.
    For installing mininet, if you are in china, i recommand you use this repo : https://gitee.com/derekwin/mininet.git

    ### Action Space
    
    # plan 1 : *rate mode
    The action is a `ndarray` with shape `(1,)` representing the pacing rate changing .

    | Num |      Action     | Min  | Max |
    |-----|-----------------|------|-----|
    | 0   |    cwnd_rate    | 0.5  | 3.0 |
    | 1   | pacing_rate_rate| 0.5  | 3.0 | <- only this

    # plan 2 : owl mode
    The action is a `ndarray` with shape `(1,)` representing the cwnd changing .
    
    spaces.Discrete(7)
    | Num |      Action     |            value           |
    |-----|-----------------|--------------|-------------|
    | 0   |    cwnd_value   | [-10, -3, -1, 0, 1, 3, 10] |

    # plan 3 : satcc mode
    The action is a `ndarray` with shape `(1,)` representing the choosen action .
    
    spaces.Discrete(3)
    | Num |      Action     |    value   |
    |-----|-----------------|------|-----|
    | 0   |    cwnd_value   | [-1, 0, 1] |
    -1 : down action
    0  : stay action
    1  : up action


    ### Observation Space

    The observation is a `ndarray` with shape `(7,)` representing the x-y coordinates of the pendulum's free
    end and its angular velocity.

    | Num | Observation      | Min  |           Max            |
    |-----|------------------|------|--------------------------|
    | 0   | cwnd             | 0.0  | np.finfo(np.float32).max |  /1460
    | 1   | pacing_rate      | 0.0  | np.finfo(np.float32).max |  /1460
    | 2   | rtt              | 0.0  | np.finfo(np.float32).max |  /512
    | 3   | min_rtt          | 0.0  | np.finfo(np.float32).max |  /512
    | 4   | srtt             | 0.0  | np.finfo(np.float32).max |  /512
    | 5   | inflight         | 0.0  | np.finfo(np.float32).max |  /16384
    | 6   | rlcclost         | 0.0  | np.finfo(np.float32).max |
    | 7   | lost_pkts        | 0.0  | np.finfo(np.float32).max |
    | 8   | is_app_limited   | 0.0  |           1.0            |

    # not in observation but in self.state
    | 9   | delivery_rate    | 0.0  | np.finfo(np.float32).max |  /1024
    | 10  | throughput       | 0.0  | np.finfo(np.float32).max |  /1024
    | 11  | sended_interval  | 0.0  | np.finfo(np.float32).max |

    ### Rewards

    The default reward function is throughput - (rtt - min_rtt)
    You can define your reward_function and set it by config['reward_function']  

    ### Arguments
    config : dict
        config['rlcc_flag'] : rlcc_flag
        config["reward_function"] : selfdefined reward function : 
            input : state : obs
            return : reward value

    """
    # metadata = {"render_modes": ["human", "rgb_array"], "render_fps": 4}

    def __init__(self, config: dict, render_mode: Optional[str] = None, redis_host: str="10.0.3.3", redis_port: int=6379):

        assert config["rlcc_flag"], "you need init rlcc_flag by config['rlcc_flag']"

        self.rlcc_flag = config["rlcc_flag"]
        self.last_state = None      # fill state while flow is over
        self.state = None

        if config.__contains__("reward_function"):
            self.reward_function = config["reward_function"]
        else:
            self.reward_function = self._reward

        channels = [f"rlccstate_{self.rlcc_flag}"]  # rlcc channel
        channels.append('mininet')  # mininet channel
        
        channels.append(f'rlccint_{self.rlcc_flag}')
        r = Redis(host=redis_host, port=redis_port)
        self.rp = Redis(host=redis_host, port=redis_port)
        pub = r.pubsub()
        pub.subscribe(channels)
        self.msg_stream = pub.listen()

        high = np.array(
            [
                np.finfo(np.float32).max,  # cwnd
                np.finfo(np.float32).max,  # pacing_rate
                np.finfo(np.float32).max,  # rtt
                np.finfo(np.float32).max,  # min_rtt
                np.finfo(np.float32).max,  # srtt
                np.finfo(np.float32).max,  # inflight
                np.finfo(np.float32).max,  # lost_interval  # 采样周期内的丢包数
                np.finfo(np.float32).max,  # lost_pkts   # sampler周期内约rtt的丢包
                np.finfo(np.float32).max,  # is_app_limited
                # np.finfo(np.float32).max,  # delivery_rate   # 后两维不放入状态空间
                # np.finfo(np.float32).max,  # throughput (sending rate)
                # np.finfo(np.float32).max,  # sended_interval 
                np.finfo(np.float32).max, # qdepth
                np.finfo(np.float32).max, # delay
                
            ],
            dtype=np.float32,
        )
        


        self.scale = np.array([1, 1, 512, 512, 512, 16384, 1, 1, 1, 1024, 1024, 1, 1, 1], dtype=np.float32)
        
        if "plan" in config.keys():
            self.plan = config["plan"]
        else:
            self.plan = 1

        if "maxsteps" in config.keys():
            self.maxsteps = config["maxsteps"]
        else:
            # 300Mb / (10Mb/s) * 33 [1000ms/(15ms*2)] = 990 
            self.maxsteps = 1800
        self.step_count = 0

        # 对应rlcc.c中 pacing rate，用倍率调整
        if self.plan == 1:
            self.action_max = 3.0
            self.action_min = 0.5
            self.action_space = spaces.Box(
                low=self.action_min, high=self.action_max, shape=(1,), dtype=np.float32
            )
        
        # owl方案，agent从给定的多个动作中选择一个
        if self.plan == 2:
            self.action_max = 10
            self.action_min = -10
            self.action_space = spaces.Discrete(7)
            self._action_to_direction = {
                0: -10,
                1: -3,
                2: -1,
                3: 0,
                4: 1,
                5: 3,
                6: 10,
            }
        # satcc方案，agent仅选择是否增加还是减少还是不动，尺度交给 自动变速器
        if self.plan == 3:
            self.up_change_EMA = 0.1
            self.up_stay_EMA = 0.1
            self.down_change_EMA = 0.1
            self.down_stay_EMA = 0.1
            self.deliver_mean = 0

            self.action_max = 1
            self.action_min = -1
            self.action_space = spaces.Discrete(3)
            self._action_to_direction = {
                0: -1,
                1: 0,
                2: 1,
            }

        self.observation_space = spaces.Box(0, high, dtype=np.float32)

        # wait until subscribe success
        # 前两次消息均是订阅消息，一次是rlcc_flag,一次是mininet
        for msg in self.msg_stream:
            print(str(msg["channel"], encoding="utf-8"), '订阅成功')
            break

    def _reward(self, state):

        # # satcc reward  : 效果差
        # dr_diff = state[-2] - state[-1]
        # goodvalue = (dr_diff*100 / (np.absolute(dr_diff) + state[-1])) + 10 # 维持稳定，适当奖励，不能太大，防止减低的惩罚太小    
        # rtt_diff = state[2] - state[4]
        # rtt_good = (rtt_diff*100 / (np.absolute(rtt_diff) + state[4])) + 5  # 增加为+ 减少为- 鼓励降低延迟 惩罚增加延迟，+5抵消波动，适当容忍延迟波动
        # reward = goodvalue - rtt_good
        
        # # base reward
        # # throughput - rtt_change(rtt - min_rtt)
        # reward = state[-2] - state[2] + state[3]

        # # owl reward
        # if state[-1]<1:
        #     state[-1]=1
        # loss = state[6] / state[-1]  # 这个丢包率是不是得长期丢包率？
        # # # sending_rate = state[-2]
        # deta = 0.5
        # reward = state[-2] - deta * (1/(1-loss)) # ?有问题，很小

        # # # aurora reward
        # if state[-1]<1:
        #     state[-1]=1
        # loss = state[6] / state[-1]  # loss of this sample interval
        # reward = 10*state[-2] - 1000*state[2] - 2000*loss  # 这个奖励在异构训练环境，奖励会不均匀

        # new reward
        # reward = state[-2] - 100*(state[2] - state[3])

        # line
        reward = state[-3] - 100*(state[2] - state[3])

        # 3log
        # reward = np.log(state[-3]/10) + np.log(state[-3]/100) + np.log(state[-3]/100) - 3*np.log(state[2] - state[3])
        # repair low bandwidth th performence.
        
        # *8/1024  log8
        # dr = state[-3]*8/1024
        # reward = np.log(dr) - np.log(state[2] - state[3])

        # up
        # dr_up = state[-3]-self.deliver_mean
        # if dr_up > 0:
        #     dr_up = np.log(dr_up)
        # elif dr_up < 0:
        #     dr_up = -np.log(-dr_up)
        # else:
        #     dr_up = 0
        # rt_up = state[2] - state[3]
        # if rt_up > 0:
        #     rt_up = np.log(rt_up)
        # elif rt_up < 0:
        #     rt_up = -np.log(-rt_up)
        # else:
        #     rt_up = 0
        # reward = dr_up - rt_up

        # # copa reward
        # # log(throughput) - beta * log(delay)
        # beta = 1
        # reward = np.log(state[-2]) - beta * np.log(state[2])

        # # mvfst reward 
        # # 发现copa的奖励函数在训练的时候, 0.5Mbps和100Mbps环境一起训练会有问题
        # # throughput - beta * delay
        # beta = 1
        # reward = state[-2] - beta * state[2]


        return reward

    def _get_obs(self):
        # also can : pub.get_message()
        for msg in self.msg_stream:
            if msg["type"] == "message":
                data_list = msg["data"].decode("utf-8").split(';')
                len_of_list = len(data_list)

                if len_of_list > 5:
                    data = np.array(data_list, dtype=np.float32)    # receive with np.int64
                    return np.divide(data, self.scale, dtype=np.float32)
                
                if len_of_list == 2:
                    return np.array(data_list, dtype=np.float32)
                
                elif len_of_list == 3:      # done
                    return np.array([0], dtype=np.float32)
                # 只处理大于5的列表
                else:
                    continue

            elif msg["type"] == "subscribe":
                continue
                # print(f'{self.rlcc_flag}', str(msg["channel"], encoding="utf-8"), 'mininet订阅成功')

    def reset(self, seed: Optional[int] = None, options: Optional[dict] = None):
        # gym环境通过reset来启动和重新开启环境
        
        self.step_count = 0
        
        # 重启新流
        self.rp.publish('redis', self.rlcc_flag)
     
        # 启动后，获取第一次状态
        self.state = self._get_obs()
        
        if len(self.state == 2):
            self.reset()
            
        if len(self.state) == 1:   # sometimes reset failed while async samplers in rllib, continue reset
                                    # tianshou 也出现了 重启失败的案例 ： 可能是上次退出的残留信息干扰了结果
                                    # 重复启动可以解决问题，但是不完美 
            self.reset()
        # print(f"reset : {self.rlcc_flag} : {self.state}")

        # # rllib 
        return self.state[:-3]      # 最后三位是专属用于计算奖励
        
    def EMA(self, new, old, rate): # rate 4, 8
        return (1/rate)*new + ((rate-1)/rate)*old

    def step(self, action):
        
        # 超时检测，太长时间没有结束，则主动结束此流
        self.step_count += 1
        if self.step_count >= self.maxsteps:
            self.rp.publish('redis', f"{self.rlcc_flag}stop")
            self.step_count = 0

            # old api
            return self.last_state[:-3], self.reward_function(self.last_state), True, {}

        # 动作处理，适应不同的RL框架
        if self.plan == 1:
            action = np.clip(action, self.action_min, self.action_max)

        if self.plan == 2:  # 离散cwnd动作
            action = self._action_to_direction[action]
            action = np.clip(action, self.action_min, self.action_max+1) # clip 左闭右开
            action = [action]

        # action # for satcc action -> -1 0 1
        cwnd_change = 0
        if self.plan == 3:
            self.deliver_mean = self.EMA(self.state[-3], self.deliver_mean, 8)
            action = self._action_to_direction[action]
            action = np.clip(action, self.action_min, self.action_max+1) # clip 左闭右开
            action_choosed = action
            if action_choosed == 0:
                self.up_stay_EMA = self.EMA(5, self.up_stay_EMA, 4)
                self.up_change_EMA = self.EMA(5, self.up_change_EMA, 4)
                self.down_stay_EMA = self.EMA(5, self.down_stay_EMA, 4)
                self.down_change_EMA = self.EMA(5, self.down_change_EMA, 4)
                # print(f"-----{action},{self.up_stay_EMA}{self.up_change_EMA}{self.down_stay_EMA}{self.down_change_EMA} --- {cwnd_change}")
            elif action_choosed == 1:
                self.up_change_EMA = self.EMA(10, self.up_change_EMA, 16) #16->4
                self.up_stay_EMA = self.EMA(0.2, self.up_stay_EMA, 16)#16->4
                self.down_change_EMA = self.EMA(5, self.down_change_EMA, 4)
                cwnd_change = (int)(self.up_change_EMA/self.up_stay_EMA)+1
                # if cwnd_change>=10:
                #     print(f"-----{action},{self.up_stay_EMA}{self.up_change_EMA}{self.down_stay_EMA}{self.down_change_EMA} --- {cwnd_change}")
            elif action_choosed == -1:
                self.down_stay_EMA = self.EMA(0.2, self.down_stay_EMA, 16)#16->4
                self.down_change_EMA = self.EMA(10, self.down_change_EMA, 16)#16->4
                self.up_change_EMA = self.EMA(5, self.up_change_EMA, 4)
                cwnd_change = -(int)(self.down_change_EMA/self.down_stay_EMA)-1
                # if cwnd_change<=-10:
                #     print(f"-----{action},{self.up_stay_EMA}{self.up_change_EMA}{self.down_stay_EMA}{self.down_change_EMA} --- {cwnd_change}")


        # print(action, type(action)) # 适配rllib，tianshou
        if isinstance(action, np.int64): # action 1
            action = [action]

        if self.plan == 3:
            action = [cwnd_change]

        # 执行动作
        # action 1 : "0.0,0.0" cwnd_rate,pacing_rate
        if self.plan == 1:
            self.rp.publish(f'rlccaction_{self.rlcc_flag}', f"0,{action[0]}")  # cwnd_rate, pacing_rate_rate # 适配rllib和tianshou
        else:
            self.rp.publish(f'rlccaction_{self.rlcc_flag}', f"{action[0]}") # cwnd_value

        # 获取下一步状态
        self.state = self._get_obs()
        
        # # 流结束
        
        if len(self.state) == 2:
            self.step()
        
        # old api
        if len(self.state) == 1:
            # # return
            return self.last_state[:-3], self.reward_function(self.last_state), True, {}
        # state, reward, done, info
        self.last_state = self.state
        # # return
        return self.state[:-3], self.reward_function(self.state), False, {}
        

    def render(self):
        return

    def close(self):
        # close
        return

    def seed(self, seed):
        np.random.seed(seed)
