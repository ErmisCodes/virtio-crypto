/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	char str[100];
	VirtQueueElement elem;
	unsigned int *syscall_type;

	DEBUG_IN();

	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	}

	DEBUG("I have got an item from VQ 0xD  ");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
    case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:{
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		int new_fd;
		/* ?? */
		// 1) open /dev/crypto
		// 2) give that file discriptor back to the vq
		new_fd = open("/dev/crypto", O_RDWR);
		if (new_fd < 0) {
        	perror("open(/dev/crypto)");
        	new_fd = -1 ;
		}
		sprintf(str, "%d", new_fd);
		DEBUG( str);
		*(int *)elem.in_sg[0].iov_base =   new_fd ; 					// NOTE: probably incorrect

		break;
    }

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:{
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		/* ?? */
		// 1)  get the file descriptor from the vq
		// 2) close that file descriptor
		// 3)  return so that you wake up the guest

		int target_fd = * (int *)elem.out_sg[1].iov_base;
		close(target_fd);
		unsigned char * input_msg = elem.in_sg[0].iov_base;
		memcpy(input_msg, "File closed successfully!", 26);
		break;
    }
	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:{
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		/* ?? */
		// 1) get the file descriptor, regardless of the specific command
		int target_fd;

		target_fd = *(int *)elem.out_sg[2].iov_base ;
		sprintf(str, "%d", target_fd);
		DEBUG( str);
		// 2) get the specific message (CIOCGSESSION, CIOCGFSESSION etc)
		char *output_msg = elem.out_sg[1].iov_base;


		if (strcmp(output_msg, "CIOCGSESSION") == 0 ){
			struct session_op * sess ;
			DEBUG("CIOCGSESSION if got in");
			sess = (struct session_op *) elem.in_sg[0].iov_base;
			sess->key = elem.out_sg[3].iov_base;
			if (ioctl(target_fd, CIOCGSESSION, sess )){
				perror("ioctl on CIOCGSESSION WENNT WRONG!");
			}
		}
		else if (strcmp(output_msg, "CIOCFSESSION") == 0 ){
			__u32 * sess_id_ptr ;
			sess_id_ptr=(__u32*)elem.out_sg[3].iov_base;
			DEBUG("CIOCFSESSION if got in");
			if (ioctl(target_fd, CIOCFSESSION, sess_id_ptr )){
				perror("ioctl on CIOCFSESSION WENNT WRONG!");
			}

		}
		else if (strcmp(output_msg, "CIOCCRYPT") == 0 ){
			struct crypt_op * crypt ;
			DEBUG("CIOCCRYPT if got in");
			crypt = (struct crypt_op *) elem.out_sg[3].iov_base ;
			crypt->src = elem.out_sg[4].iov_base;
			crypt->iv = elem.out_sg[5].iov_base;
			crypt->dst = elem.in_sg[0].iov_base;
			if (ioctl(target_fd, CIOCCRYPT, crypt )){
				perror("ioctl on CRYPT WENNT WRONG!");
			}
		}
		else {
			perror ("unsupported message on ioctl detected!");
		}

		break;
		}

	default:
		DEBUG("Unknown syscall_type");
	}

	DEBUG("pussying");
	virtqueue_push(vq, &elem, 0);        // NOTE: Len usage?
	DEBUG("notifying");
	virtio_notify(vdev, vq);
	DEBUG("doneno");

}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
