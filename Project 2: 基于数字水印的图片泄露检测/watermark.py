import cv2
import numpy as np
from matplotlib import pyplot as plt
from skimage.util import random_noise
from skimage.transform import rotate
from skimage import exposure


# 字符串转二进制
def str_to_bits(s: str) -> str:
    return ''.join(format(ord(c), '08b') for c in s)


def bits_to_str(bits: str) -> str:
    out = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) == 8:
            out.append(chr(int(byte, 2)))
    return ''.join(out)


# 生成嵌入位置
def make_block_positions(height, width, offset=(3, 3), seed=42):
    xs = []
    ox, oy = offset
    for i in range(0, height, 8):
        for j in range(0, width, 8):
            x, y = i + ox, j + oy
            if x < height and y < width:
                xs.append((x, y))
    rng = np.random.RandomState(seed)
    rng.shuffle(xs)
    return xs


# 水印嵌入
def embed_watermark(original_img_path, watermark_text, output_path, alpha=0.12, repeat_times=5):
    original_img = cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE)
    if original_img is None:
        raise ValueError("无法读取原图")

    h, w = original_img.shape
    dct = cv2.dct(np.float32(original_img) / 255.0)

    wm_bits = str_to_bits(watermark_text)
    L = len(wm_bits)

    positions = make_block_positions(h, w, offset=(3, 3), seed=42)
    need = L * repeat_times
    if need > len(positions):
        raise ValueError("水印太大或重复次数过多")

    watermarked_dct = dct.copy()
    for idx, bit in enumerate(wm_bits):
        for r in range(repeat_times):
            x, y = positions[idx * repeat_times + r]
            watermarked_dct[x, y] += (alpha if bit == '1' else -alpha)

    watermarked_img = cv2.idct(watermarked_dct)
    watermarked_img = np.uint8(np.clip(watermarked_img * 255, 0, 255))
    cv2.imwrite(output_path, watermarked_img)
    return watermarked_img


# 简单相似度
def _ncc(a, b):
    a = a.astype(np.float32)
    b = b.astype(np.float32)
    a = (a - a.mean()) / (a.std() + 1e-6)
    b = (b - b.mean()) / (b.std() + 1e-6)
    return float((a * b).mean())


# ORB特征匹配对齐
def try_orb_align(attacked, original):
    h, w = original.shape[:2]
    orb = cv2.ORB_create(nfeatures=3000)
    k1, d1 = orb.detectAndCompute(attacked, None)
    k2, d2 = orb.detectAndCompute(original, None)
    if d1 is None or d2 is None or len(k1) < 12 or len(k2) < 12:
        return None

    bf = cv2.BFMatcher(cv2.NORM_HAMMING)
    matches = bf.knnMatch(d1, d2, k=2)
    good = [m for m, n in matches if m.distance < 0.75 * n.distance]
    if len(good) < 8:
        return None

    src_pts = np.float32([k1[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
    dst_pts = np.float32([k2[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)

    H, _ = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
    if H is not None:
        return cv2.warpPerspective(attacked, H, (w, h))

    M, _ = cv2.estimateAffinePartial2D(src_pts, dst_pts, method=cv2.RANSAC)
    if M is not None:
        return cv2.warpAffine(attacked, M, (w, h))
    return None


# 相位相关对齐（平移补偿）
def try_phase_align(attacked, original):
    h, w = original.shape[:2]
    a = (cv2.GaussianBlur(attacked.astype(np.float32), (5, 5), 0) - attacked.mean()) / (attacked.std() + 1e-6)
    o = (cv2.GaussianBlur(original.astype(np.float32), (5, 5), 0) - original.mean()) / (original.std() + 1e-6)
    (dx, dy), _ = cv2.phaseCorrelate(a, o)
    M = np.float32([[1, 0, dx], [0, 1, dy]])
    return cv2.warpAffine(attacked, M, (w, h))


# 总对齐方法（原图+翻转，选最优）
def align_to_original(attacked_img, original_img):
    h, w = original_img.shape[:2]
    base = attacked_img if attacked_img.shape == original_img.shape else cv2.resize(attacked_img, (w, h))

    candidates = []
    for variant in [base, cv2.flip(base, 1)]:
        aligned = try_orb_align(variant, original_img)
        if aligned is not None:
            candidates.append(aligned)
        candidates.append(try_phase_align(variant, original_img))

    candidates.append(cv2.resize(attacked_img, (w, h)))

    best = max(candidates, key=lambda c: _ncc(np.clip(c, 0, 255).astype(np.uint8), original_img))
    return np.clip(best, 0, 255).astype(np.uint8)


# 提取水印
def extract_watermark(watermarked_img_path, original_img_path, watermark_length_bits, alpha=0.12, repeat_times=5):
    original_img = cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE)
    watermarked_img_raw = cv2.imread(watermarked_img_path, cv2.IMREAD_GRAYSCALE)
    if original_img is None or watermarked_img_raw is None:
        raise ValueError("无法读取图像")

    watermarked_img = align_to_original(watermarked_img_raw, original_img)

    original_dct = cv2.dct(np.float32(original_img) / 255.0)
    watermarked_dct = cv2.dct(np.float32(watermarked_img) / 255.0)

    positions = make_block_positions(*original_img.shape, offset=(3, 3), seed=42)
    need = watermark_length_bits * repeat_times
    if need > len(positions):
        raise ValueError("参数不匹配，位置不足")

    extracted_bits = []
    for idx in range(watermark_length_bits):
        votes = []
        for r in range(repeat_times):
            x, y = positions[idx * repeat_times + r]
            diff = watermarked_dct[x, y] - original_dct[x, y]
            votes.append('1' if diff > 0 else '0')
        extracted_bits.append('1' if votes.count('1') >= votes.count('0') else '0')

    bits = ''.join(extracted_bits)
    return bits_to_str(bits), bits


# 计算准确率
def bit_accuracy(bits_true: str, bits_pred: str) -> float:
    n = min(len(bits_true), len(bits_pred))
    return sum(a == b for a, b in zip(bits_true[:n], bits_pred[:n])) / n if n else 0.0


def char_accuracy(s_true: str, s_pred: str) -> float:
    n = min(len(s_true), len(s_pred))
    return sum(a == b for a, b in zip(s_true[:n], s_pred[:n])) / n if n else 0.0


# 测试鲁棒性
def test_robustness(watermarked_img_path, original_img_path, watermark_text, alpha=0.12, repeat_times=5):
    watermarked_img = cv2.imread(watermarked_img_path, cv2.IMREAD_GRAYSCALE)
    original_img = cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE)

    attacks = {
        'noise': lambda img: (random_noise(img, mode='gaussian', var=0.01) * 255).astype(np.uint8),
        'rotate_5': lambda img: (rotate(img, 5, resize=True) * 255).astype(np.uint8),
        'rotate_15': lambda img: (rotate(img, 15, resize=True) * 255).astype(np.uint8),
        'rotate_30': lambda img: (rotate(img, 30, resize=True) * 255).astype(np.uint8),
        'crop_10': lambda img: img[int(img.shape[0] * 0.1):, int(img.shape[1] * 0.1):],
        'brightness': lambda img: (exposure.adjust_gamma(img, gamma=0.6) * 255).astype(np.uint8),
        'contrast': lambda img: (exposure.adjust_log(img, gain=0.9) * 255).astype(np.uint8),
        'flip': lambda img: cv2.flip(img, 1),
        'jpeg_q70': lambda img: cv2.imdecode(cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 70])[1], 0),
        'jpeg_q40': lambda img: cv2.imdecode(cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 40])[1], 0),
        'shift_5_5': lambda img: cv2.warpAffine(img, np.float32([[1, 0, 5], [0, 1, 5]]), (img.shape[1], img.shape[0]))
    }

    results = {}
    wm_bits_true = str_to_bits(watermark_text)

    for name, func in attacks.items():
        attacked = np.clip(func(watermarked_img), 0, 255).astype(np.uint8)
        aligned = align_to_original(attacked, original_img)
        temp_path = f'temp_{name}.png'
        cv2.imwrite(temp_path, aligned)

        try:
            extracted_text, extracted_bits = extract_watermark(
                temp_path, original_img_path, len(watermark_text) * 8,
                alpha=alpha, repeat_times=repeat_times
            )
            results[name] = {
                'bit_acc': bit_accuracy(wm_bits_true, extracted_bits),
                'char_acc': char_accuracy(watermark_text, extracted_text),
                'extracted': extracted_text
            }
        except Exception as e:
            results[name] = {'bit_acc': 0.0, 'char_acc': 0.0, 'extracted': '', 'err': str(e)}

    return results


def main():
    original_img_path = 'original.png'
    watermarked_img_path = 'watermarked.png'
    watermark_text = '2025hh1605'

    alpha = 0.12
    repeat_times = 5

    print("嵌入水印...")
    watermarked_img = embed_watermark(
        original_img_path, watermark_text, watermarked_img_path,
        alpha=alpha, repeat_times=repeat_times
    )

    print("\n提取原始水印...")
    extracted, _bits = extract_watermark(
        watermarked_img_path, original_img_path, len(watermark_text) * 8,
        alpha=alpha, repeat_times=repeat_times
    )
    print(f"原始: {watermark_text}")
    print(f"提取: {extracted}")

    print("\n鲁棒性测试...")
    results = test_robustness(
        watermarked_img_path, original_img_path, watermark_text,
        alpha=alpha, repeat_times=repeat_times
    )

    print("\n测试结果：")
    for k, v in results.items():
        print(f"{k:12s}: bit_acc={v['bit_acc']:.2%}, char_acc={v['char_acc']:.2%}, extracted='{v['extracted']}'")

    plt.figure(figsize=(12, 6))
    plt.subplot(1, 2, 1)
    plt.imshow(cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE), cmap='gray')
    plt.title('Original')
    plt.axis('off')

    plt.subplot(1, 2, 2)
    plt.imshow(watermarked_img, cmap='gray')
    plt.title('Watermarked')
    plt.axis('off')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
