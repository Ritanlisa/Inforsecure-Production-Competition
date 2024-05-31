from models.cnn2d import cnn2d as train_model
from flowcontainer.extractor import extract
from utils.pcap_decode import PcapDecode
from kamene.all import rdpcap
import numpy as np
import collections
import torch
import csv
import os

model_path = "./ckpt/cnn2d.pth"
payload_dir = "./flowcontainer/pay_load.npy"
sequence_dir = "./flowcontainer/ip_length.npy"
test_label = "./flowcontainer/label.npy"
threshold = 0
ip_length = 128
packet_num = 8
byte_num = 512
statistic_file = None
label_dict = {
    "Adware-pcaps": 0,
    "Benign-pcaps": 1,
    "Ransomware-pcaps": 2,
    "Scareware-pcaps": 3,
    "SMSmalware-pcaps": 4,
}
BATCH_SIZE = 128


def hex_to_dec(hex_str, target_length):
    dec_list = []
    for i in range(0, len(hex_str), 2):
        dec_list.append(int(hex_str[i : i + 2], 16))
    dec_list = pad_or_truncate(dec_list, target_length)
    return dec_list


def pad_or_truncate(some_list, target_len):
    return some_list[:target_len] + [0] * (target_len - len(some_list))


def get_pay_seq(pcap, threshold, ip_length, n, m):
    """
    :param pcap: 原始pcap
    :param n: 前n个包
    :param m: 前m字节
    :return:
    """
    result = extract(pcap, extension=["tcp.payload", "udp.payload"])
    # 假设有k个流
    pay_load = []
    seq_load = []
    for key in result:
        value = result[key]
        ip_len = value.ip_lengths
        if len(ip_len) < threshold:
            continue
        # 统一长度
        ip_len = pad_or_truncate(ip_len, ip_length)
        seq_load.append(ip_len)
        packet_num = 0
        if "tcp.payload" in value.extension:
            # 提取tcp负载
            tcp_payload = []
            for packet in value.extension["tcp.payload"]:
                if packet_num < n:
                    # packet[0]是负载，1是标注该报文在流的顺序
                    load = packet[0]
                    tcp_payload.extend(hex_to_dec(load, m))
                    packet_num += 1
                else:
                    break
            # 当前包数太少，加0
            if packet_num < n:
                tcp_payload = pad_or_truncate(tcp_payload, m * n)
            pay_load.append(tcp_payload)
        elif "udp.payload" in value.extension:
            # 提取ucp负载
            udp_payload = []
            for packet in value.extension["udp.payload"]:
                if packet_num < n:
                    # packet[0]是负载，1是标注该报文在流的顺序
                    load = packet[0]
                    udp_payload.extend(hex_to_dec(load, m))
                    packet_num += 1
                else:
                    break
            # 当前包数太少，加0
            if packet_num < n:
                udp_payload = pad_or_truncate(udp_payload, m * n)
            pay_load.append(udp_payload)
    pay_load = np.array(pay_load)
    seq_load = np.array(seq_load)
    return pay_load, seq_load


def test_with_trained_model(pcap):
    num_classes = len(label_dict)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = train_model(model_path, pretrained=False, num_classes=num_classes).to(
        device
    )
    checkpoint = torch.load(model_path, map_location=device)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    pay, seq = get_pay_seq(pcap, threshold, ip_length, packet_num, byte_num)
    label = np.full((seq.shape[0],), 0)

    test_loader = torch.utils.data.DataLoader(
        dataset=torch.utils.data.TensorDataset(
            torch.from_numpy(
                np.array(pay).reshape(-1, 1, np.array(pay).shape[1])
            ).float(),
            torch.from_numpy(
                np.array(seq).reshape(-1, np.array(seq).shape[1], 1)
            ).float(),
            torch.rand(len(pay), len(pay[0])),
            torch.from_numpy(label).long(),
        ),
        batch_size=BATCH_SIZE,
        shuffle=True,
        pin_memory=True,
        num_workers=1,
    )

    # 预测并输出标签
    all_preds = []
    index2label = {j: i for i, j in label_dict.items()}
    with torch.no_grad():
        for data, seq_data, sta_data, label_data in test_loader:
            data, seq_data, sta_data = (
                data.to(device),
                seq_data.to(device),
                sta_data.to(device),
            )
            outputs, _ = model(data, seq_data, sta_data)
            _, preds = torch.max(outputs, 1)
            for i in range(len(preds)):
                all_preds.append(index2label[preds[i].item()])

    # 将索引标签转换回原始类别标签
    return all_preds

def get_all_pcap(PCAPS, PD):
    '''
    对于pcap文件进行文件处理，返回字典格式
    '''
    pcaps = collections.OrderedDict()
    for count, i in enumerate(rdpcap(PCAPS), 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps

if __name__ == "__main__":
    test_pcap_addr = r"C:\Users\Ritanlisa\Desktop\Inforsecure-Production-Competition\pcaps\123.pcap"
    all_preds = test_with_trained_model(test_pcap_addr)
    PD = PcapDecode()
    pcaps = get_all_pcap(test_pcap_addr, PD)
    print(len(all_preds))
    print(len(pcaps))
