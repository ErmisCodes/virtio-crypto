/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>  ( GNU )
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

#define MSG_LEN 100
/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;
	unsigned int *syscall_type;
	int *host_fd, *reply_fd;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, *sgs[2];

	debug("Entering guest open ");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;
	reply_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)   // NOTE: This is the actual fd in the guest side
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor",
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;				// NOTE: The file descriptor in the host's side <3
	filp->private_data = crof;
	vq = crdev->vq;
	/**
	 * We need two sg lists, one for syscall_type and one to get the 			NOTE: [0] for type and [1] for fd
	 * file descriptor from the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));  // create a scatter list with our syscall on the first position
	sgs[0] = &syscall_type_sg;  // create a scatter list


	sg_init_one(&input_msg_sg, reply_fd, sizeof(reply_fd));			// this is where we are awaiting the response
	sgs[1] = &input_msg_sg;

	spin_lock(&crdev ->device_lock);
	err = virtqueue_add_sgs(vq, sgs, 1, 1, &syscall_type_sg, GFP_ATOMIC);
	spin_unlock(&crdev ->device_lock);
	virtqueue_kick(vq);


	/**
	 * Wait for the host to process our data.
	 **/
	 debug("before virtqueue_get_buf\n");
	while (virtqueue_get_buf(vq, &len) == NULL)
		;
	/* If host failed to open() return -ENODEV. */
	if ( *reply_fd == -1 ){
		ret = -ENODEV ;
	}

	crof->host_fd = * reply_fd ;
	printk("FD returned: %d\n",*reply_fd);

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0,err;
	unsigned int num_in, num_out ;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, *sgs[3];
	unsigned int *syscall_type;
	unsigned int len;
	unsigned char * input_msg  ;
	int *target_fd; // get the file descriptor that we want to close


	debug("Entering");
	target_fd = kzalloc(sizeof(*target_fd), GFP_KERNEL);
	*target_fd  = crof -> host_fd;
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	input_msg = kzalloc(MSG_LEN, GFP_KERNEL);

	/**
	 * Send data to the host.   ( close )
	 **/
	 sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	 sgs[0] = &syscall_type_sg;  // NOTE: at sgs[0]: SYSCALL TYPE, sgs[1]: OUTPUT MESSAGE
	 // NOTE: We need to put the file descriptor here

	 sg_init_one(&output_msg_sg,target_fd , sizeof(*target_fd));
	 sgs[1] = &output_msg_sg;  //fd to be closed


	sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
	sgs[2] = &input_msg_sg;

	spin_lock(&crdev ->device_lock);
	err = virtqueue_add_sgs(vq, sgs, 2, 1, &syscall_type_sg, GFP_ATOMIC);
	spin_unlock(&crdev ->device_lock);
	virtqueue_kick(vq);


	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(vq, &len) == NULL) ;

	debug("Host answered: '%s'", input_msg);
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg,
	 								    arg_sg_out,arg_sg_in, fd_sg,key_sg, mac_sg,
										src_sg,dst_sg,iv_sg,sess_id_sg, *sgs[7];
	unsigned int num_out, num_in, len;

	unsigned char *output_msg;
	unsigned int *syscall_type;
	void * wildcard ;
	int arg_size;
	int * target_fd ;
	void * user_key = NULL,*user_iv=NULL,*user_src=NULL,*user_dst=NULL;
	wildcard = NULL;
	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	target_fd = kzalloc(sizeof(int), GFP_KERNEL);


	*target_fd  = crof -> host_fd;
	num_out = 0;
	num_in = 0;
	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;  // NOTE: at sgs[0]: SYSCALL TYPE

	arg_size = (cmd == CIOCCRYPT)? sizeof(struct crypt_op) : sizeof(struct session_op);

	/**
	 *  Add all the cmd specific sg lists.
	 **/

	 /**
	 sgs->out:	syscall_type_sg
	 	  		output_msg (CIOCGSESSION || CIOCFSESSION || CIOCCRYPT)
				host fd
				key
	 	  in:	session_op || crypt_op
	 **/

	switch (cmd) {
	case CIOCGSESSION:{
		struct session_op* wildcard_session ;
		void *wildcard_key;
		void *wildcard_mackey;
		debug("CIOCGSESSION");   // NOTE: in output[1] we put the IOCTL action in question
		memcpy(output_msg, "CIOCGSESSION", 13);

		wildcard_session = kzalloc(arg_size,GFP_KERNEL);
		if(copy_from_user((void *  )wildcard_session,(void *)arg,arg_size)){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}   // copy from user the arguement session

		user_key = wildcard_key = wildcard_session->key;
		wildcard_session->key = kzalloc(sizeof(__u8)*wildcard_session->keylen, GFP_KERNEL);
		if(copy_from_user (wildcard_session->key,wildcard_key,  sizeof(__u8)* (wildcard_session->keylen) )){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}	//copy from user the key

		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&fd_sg, target_fd, sizeof(int));
		sgs[num_out++] = &fd_sg;
		//key
		sg_init_one(&key_sg, wildcard_session->key, sizeof(__u8)*wildcard_session->keylen);
		sgs[num_out++] = &key_sg;
		// sg_init_one(&mac_sg, wildcard_session->mackey, sizeof(__u8)*wildcard_session->mackeylen);
		// sgs[num_out++] = &mac_sg;

		// NOTE: arg WAS wildcard
		sg_init_one(&arg_sg_out,(void *)wildcard_session, arg_size);
		sgs[num_out + (num_in++)] = &arg_sg_out;

		wildcard = (void *) wildcard_session;

		break;
	}
	case CIOCFSESSION:{
		// struct session_op* wildcard_session ;
		__u32 * sess_id;
		sess_id = kzalloc(sizeof(__u32),GFP_KERNEL);
		debug("CIOCFSESSION");   // NOTE: in output[1] we put the IOCTL action in question
		memcpy(output_msg, "CIOCFSESSION", 13);


		if(copy_from_user(sess_id,(void *)arg,sizeof(__u32))){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&fd_sg, target_fd, sizeof(int));
		sgs[num_out++] = &fd_sg;
		sg_init_one(&sess_id_sg,sess_id,sizeof(sess_id));
		sgs[num_out++]=&sess_id_sg;

		// sg_init_one(&arg_sg_out,(void *)wildcard_session, arg_size);
		// sgs[num_out + num_in++] = &arg_sg_out;

		// wildcard = (void *) wildcard_session;

		break;
	}
	case CIOCCRYPT:{
		struct crypt_op* wildcard_crypt;
		__u8 *src_ptr,*dst_ptr, *iv_ptr;


		debug("CIOCCRYPT");
		memcpy(output_msg, "CIOCCRYPT", 10);

		wildcard_crypt = kzalloc(arg_size,GFP_KERNEL);
		if(copy_from_user((void *  )wildcard_crypt,(void *)arg,arg_size)){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}   // copy from user the crypt struct

		user_src = src_ptr = wildcard_crypt->src;
		 wildcard_crypt->src = kzalloc(sizeof(__u8)*wildcard_crypt->len,GFP_KERNEL);
		if(copy_from_user((void *  )wildcard_crypt->src, (void *)src_ptr, sizeof(__u8)*(wildcard_crypt->len))){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}   // copy from user the crypt

		user_iv = iv_ptr = wildcard_crypt->iv;
		wildcard_crypt->iv = kzalloc(sizeof(__u8)*16,GFP_KERNEL);
		if(copy_from_user((void *)wildcard_crypt->iv, (void *  )iv_ptr, sizeof(__u8)*16)){
			debug("copy_from_user FAILED");
			ret = -EFAULT;
		}   // copy from user the crypt


		wildcard_crypt->dst = (unsigned char *)kzalloc(sizeof(unsigned char )*(wildcard_crypt->len),GFP_KERNEL);
		dst_ptr = wildcard_crypt->dst;

		//--OUT:
		//syscall
		//output_msg
		//fd
		//crypt struct
		//src
		//iv
		//--IN:
		//dst
		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		sgs[num_out++] = &output_msg_sg;
		sg_init_one(&fd_sg, target_fd, sizeof(int));
		sgs[num_out++] = &fd_sg;
		sg_init_one(&arg_sg_out,wildcard_crypt,sizeof(struct crypt_op));
		sgs[num_out++] = &arg_sg_out;
		sg_init_one(&src_sg,wildcard_crypt->src,wildcard_crypt->len*sizeof(unsigned char));
		sgs[num_out++] = &src_sg;
		sg_init_one(&iv_sg,wildcard_crypt->iv,16*sizeof(unsigned char));
		sgs[num_out++] = &iv_sg;
		user_dst = wildcard_crypt->dst;
		sg_init_one(&dst_sg,user_dst,wildcard_crypt->len*sizeof(unsigned char));
		sgs[num_out + num_in++] = &dst_sg;
		debug("dummy->len(1): %d",wildcard_crypt->len);
		wildcard = (struct crypt_op *)wildcard_crypt;
		break;
	}
	default:{
		wildcard = NULL;
		debug("Unsupported ioctl command");
		break;
	}

	}
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */   // NOTE: ?
	debug(" The num out is %d and the num in is %d ", num_out, num_in );
	spin_lock(&crdev ->device_lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock(&crdev ->device_lock);

	if(cmd == CIOCCRYPT){
		struct crypt_op * dummy;
		int i;
		__u8 * wildcard_dst;
		wildcard_dst = user_dst;
		dummy = (struct crypt_op *)wildcard;
		debug("dummy->len(2): %d",dummy->len);
		// debug("*******");
		// for (i = 0; i < 100; i++) {
		// 	debug("%c-%d",*((unsigned char *)dummy->src+i),i);
		// }
		if(copy_to_user((void *)((struct crypt_op *) arg)->dst, (void *)(wildcard_dst),
								dummy->len*sizeof(unsigned char))){
			debug("copy_to_user FAILED");
			ret = -1;
		}
	}else if(cmd == CIOCGSESSION){
		if(copy_to_user((void *)arg,wildcard,arg_size)){
			debug("copy_to_user FAILED");
			ret = -1;
		}
		((struct session_op*)arg)->key = user_key;
	}
	debug("We are at the end");

	kfree(output_msg);
	kfree(syscall_type);
	kfree(wildcard);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops =
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
